# =============================================================================
# AKS Adversary Lab - Logging Smoke Test
# =============================================================================
# PURPOSE
#   Detection engineering is worthless if the telemetry never arrives. This is a
#   smoke test that PROVES the logging pipeline works end to end before you rely
#   on it (to run attack simulations) or tear the lab down.
#
# HOW IT PROVES IT
#   1. It performs a few known Kubernetes actions (create a pod, list secrets)
#      tagged with a unique per-run MARKER string.
#   2. It then polls Log Analytics, looking specifically for THAT marker in each
#      expected table — not just "any data". Finding the marker proves OUR action
#      traversed: kube-apiserver -> diagnostic settings -> Log Analytics ingestion.
#   3. It prints PASS/FAIL per table and exits non-zero if any table stayed empty,
#      so it can gate CI or a runbook step.
#
# WHY A MARKER (not just "row count > 0")
#   A busy cluster always has ambient traffic, so "the table has rows" could be
#   stale/unrelated data. A unique marker removes that ambiguity — it can only be
#   there if this run's activity actually flowed through.
#
# INGESTION LAG: Log Analytics typically lags 5-10 minutes, so the script polls
#   with a timeout (default 15m) rather than checking once.
#
# Usage:
#   ./verify-logging.ps1 -ResourceGroupName "rg-purpleshell-aks-lab"
#   ./verify-logging.ps1 -ResourceGroupName "rg-..." -ClusterName "purpleshell-aks"
#   ./verify-logging.ps1 -ResourceGroupName "rg-..." -SkipActivity   # rely on existing telemetry
#
# Prerequisites:
#   - Az PowerShell module (Install-Module Az); logged in: Connect-AzAccount
#   - kubectl pointed at the lab cluster (az aks get-credentials + kubelogin)
# =============================================================================

[CmdletBinding()]
param(
    # -- Required. Resource group holding the Log Analytics workspace (and cluster). --
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    # Optional explicit workspace name; auto-resolved if the RG has exactly one.
    [Parameter()]
    [string]$WorkspaceName,

    # Optional cluster name. When set, the script refuses to run if kubectl's
    # current context doesn't reference it — a guard against generating activity
    # on the WRONG cluster.
    [Parameter()]
    [string]$ClusterName,

    # Namespace the test pod is created in.
    [Parameter()]
    [string]$Namespace = "default",

    # The tables that must show data for the pipeline to be considered healthy.
    [Parameter()]
    [string[]]$Tables = @("AKSAudit", "AKSAuditAdmin", "AKSControlPlane", "ContainerLogV2"),

    # How long to keep polling before declaring a table failed (ingestion lag).
    [Parameter()]
    [int]$TimeoutMinutes = 15,

    # Skip generating activity and just check for any recent rows — useful when
    # telemetry already exists and you only want to confirm ingestion is flowing.
    [Parameter()]
    [switch]$SkipActivity
)

# Abort on first error so we don't, e.g., poll a workspace we failed to resolve.
$ErrorActionPreference = "Stop"

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step {
    param([string]$Message)
    Write-Host "`n▶ $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "  ✓ $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "  · $Message" -ForegroundColor Gray
}

function Write-Fail {
    param([string]$Message)
    Write-Host "  ✗ $Message" -ForegroundColor Red
}

# Marker-based predicate per table — proves OUR activity flowed, not just ambient
# traffic. Tables without a reliable searchable field fall back to "any recent row".
$MarkerPredicate = @{
    "AKSAudit"       = 'RequestUri has "{0}"'
    "AKSAuditAdmin"  = 'RequestUri has "{0}"'
    "ContainerLogV2" = 'LogMessage has "{0}"'
}

# ── Validate Azure context ────────────────────────────────────────────────────

Write-Step "Validating Azure context"

$context = Get-AzContext
if (-not $context) {
    throw "Not logged in. Run Connect-AzAccount first."
}
Write-Info "Subscription: $($context.Subscription.Id)"

# ── Resolve Log Analytics workspace ──────────────────────────────────────────

Write-Step "Resolving Log Analytics workspace in '$ResourceGroupName'"

if ($WorkspaceName) {
    $workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
} else {
    $workspaces = @(Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName)
    if ($workspaces.Count -eq 0) {
        throw "No Log Analytics workspace found in '$ResourceGroupName'. Pass -WorkspaceName."
    }
    if ($workspaces.Count -gt 1) {
        throw "Multiple workspaces in '$ResourceGroupName'. Pass -WorkspaceName. Found: $($workspaces.Name -join ', ')"
    }
    $workspace = $workspaces[0]
}

$customerId = $workspace.CustomerId.Guid
Write-Success "Workspace: $($workspace.Name)  (CustomerId $customerId)"

# ── Optional kubectl context safety check ────────────────────────────────────

if ($ClusterName) {
    $currentContext = (kubectl config current-context) 2>$null
    if ($currentContext -notlike "*$ClusterName*") {
        Write-Fail "kubectl context is '$currentContext', expected it to contain '$ClusterName'."
        throw "Refusing to generate activity against the wrong cluster. Switch context or fix -ClusterName."
    }
    Write-Info "kubectl context: $currentContext"
}

# ── Generate known activity ──────────────────────────────────────────────────

$marker = "logtest-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"

if (-not $SkipActivity) {
    Write-Step "Generating known activity (marker: $marker)"

    # container stdout -> ContainerLogV2 ; pod create -> AKSAudit/AKSAuditAdmin ; scheduling -> AKSControlPlane
    kubectl run $marker --namespace $Namespace --image=busybox:stable --restart=Never `
        --command -- sh -c "echo $marker; sleep 30" | Out-Null
    Write-Success "Created pod '$marker' in namespace '$Namespace'"

    # cluster-wide secret list -> AKSAudit (read)
    kubectl get secrets --all-namespaces | Out-Null
    Write-Success "Listed secrets cluster-wide"

    Write-Info "Cleaning up test pod..."
    kubectl delete pod $marker --namespace $Namespace --ignore-not-found=true --wait=false | Out-Null
} else {
    Write-Info "Skipping activity generation (-SkipActivity) — checking for any recent rows instead"
}

# ── Poll each table ──────────────────────────────────────────────────────────

Write-Step "Polling Log Analytics (timeout ${TimeoutMinutes}m; ingestion lag is typically 5-10 min)"

function Test-TableHasData {
    param(
        [string]$WorkspaceId,
        [string]$Table,
        [string]$Predicate
    )

    $filter = ""
    if ($Predicate) {
        $filter = "| where $Predicate "
    }
    $query = "$Table | where TimeGenerated > ago(30m) $filter| summarize Count = count()"

    try {
        $response = Invoke-AzOperationalInsightsQuery -WorkspaceId $WorkspaceId -Query $query -ErrorAction Stop
        $row = $response.Results | Select-Object -First 1
        if ($null -eq $row) { return 0 }
        return [int]$row.Count
    } catch {
        # Table may not exist until its first ingestion — treat as "not ready yet".
        return -1
    }
}

$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$pending  = [System.Collections.Generic.List[string]]::new()
$Tables | ForEach-Object { $pending.Add($_) }
$results  = @{}

while ($pending.Count -gt 0 -and (Get-Date) -lt $deadline) {
    foreach ($table in @($pending)) {

        $predicate = $null
        if (-not $SkipActivity -and $MarkerPredicate.ContainsKey($table)) {
            $predicate = ($MarkerPredicate[$table] -f $marker)
        }

        $count = Test-TableHasData -WorkspaceId $customerId -Table $table -Predicate $predicate

        if ($count -gt 0) {
            Write-Success "$table — $count matching row(s) in last 30m"
            $results[$table] = $count
            [void]$pending.Remove($table)
        } elseif ($count -eq 0) {
            Write-Info "$table — no matching rows yet, waiting..."
        } else {
            Write-Info "$table — table not present yet (no ingestion so far), waiting..."
        }
    }

    if ($pending.Count -gt 0) {
        Start-Sleep -Seconds 30
    }
}

# ── Report ────────────────────────────────────────────────────────────────────

Write-Step "Result"

$failed = 0
foreach ($table in $Tables) {
    if ($results.ContainsKey($table)) {
        Write-Success "PASS  $table  ($($results[$table]) row(s))"
    } else {
        Write-Fail "FAIL  $table  (no data within ${TimeoutMinutes}m)"
        $failed++
    }
}

Write-Host ""
if ($failed -eq 0) {
    Write-Host "  All $($Tables.Count) tables receiving data — logging pipeline verified." -ForegroundColor Green
    Write-Host "  Safe to run attack simulations, or tear the lab down." -ForegroundColor Gray
    exit 0
}

Write-Host "  $failed of $($Tables.Count) table(s) had no data." -ForegroundColor Red
Write-Host "  Ingestion can lag 5-10 min on a fresh cluster — re-run with a larger -TimeoutMinutes." -ForegroundColor Yellow
Write-Host "  If AKSAudit specifically is empty, confirm the diagnostic settings use resource-specific tables." -ForegroundColor Yellow
exit 1
