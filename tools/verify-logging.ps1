# =============================================================================
# AKS Adversary Lab - Logging Smoke Test
# =============================================================================
# Confirms the telemetry pipeline is flowing end to end before you tear the lab
# down. Generates known control-plane + container activity (tagged with a unique
# marker), then polls Log Analytics until each expected table shows that activity.
# Prints PASS/FAIL per table and exits non-zero if anything is missing.
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
    [Parameter(Mandatory)]
    [string]$ResourceGroupName,

    [Parameter()]
    [string]$WorkspaceName,

    [Parameter()]
    [string]$ClusterName,

    [Parameter()]
    [string]$Namespace = "default",

    [Parameter()]
    [string[]]$Tables = @("AKSAudit", "AKSAuditAdmin", "AKSControlPlane", "ContainerLogV2"),

    [Parameter()]
    [int]$TimeoutMinutes = 15,

    [Parameter()]
    [switch]$SkipActivity
)

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
