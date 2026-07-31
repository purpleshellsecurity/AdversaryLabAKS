<#
.SYNOPSIS
    Deploys the AKS Adversary Lab - MITRE ATT&CK Containers environment.

.DESCRIPTION
    Automated deployment of a fully instrumented AKS cluster for adversary
    simulation and detection engineering, aligned to the MITRE ATT&CK
    Containers matrix. Deploys AKS with full diagnostic logging,
    Container Insights, Defender for Containers, Sentinel, ACR, and Key Vault.

    THIS IS THE LOCAL ALTERNATIVE to the GitHub Actions deploy workflow
    (deploy.yaml). Same end result, but run interactively from your own machine
    instead of via CI/OIDC — handy for experimentation or when you don't want to
    wire up the federated-credential setup (see tools/setup-oidc.ps1).

    FLOW (top-to-bottom, see "Main Execution" at the bottom):
      1. Test-Prerequisites        — verify tooling + Bicep templates are present
      2. Get-InteractiveParameters — resolve/prompt for every deploy input
      3. Initialize-AzureContext   — log in and select the subscription
      4. Show-ConfigurationSummary — print the plan and get a cost-aware y/n
      5. New-LabResourceGroup      — create the tagged resource group
      6. Deploy-Infrastructure     — main.bicep (RG-scoped: AKS + logging + ...)
      7. Deploy-SubscriptionResources — main_subscription.bicep (Defender, etc.)
      8. Set-KubectlAccess         — pull cluster credentials for kubectl
      9. Install-KubernetesManifests — apply namespaces, netpol, RBAC, victims
     10. Show-DeploymentSummary    — outputs + copy/paste post-deploy steps

    Two Bicep templates are used because Azure deployments are scoped: most
    resources live inside the resource group (main.bicep), but a few — Defender
    plans, subscription Activity-log routing — must be deployed at SUBSCRIPTION
    scope (main_subscription.bicep).

.PARAMETER Location
    Azure region for deployment (default: eastus2).

.PARAMETER AdminGroupObjectId
    Entra ID group Object ID for AKS cluster-admin access.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER AuthorizedIpRange
    Your public IP for API server authorized access (auto-detected if omitted).

.EXAMPLE
    ./infrastructure/aks_adversary_lab_deploy.ps1

.EXAMPLE
    ./infrastructure/aks_adversary_lab_deploy.ps1 -Location "eastus2" -AdminGroupObjectId "abc-123"
#>

# All params are optional here: anything not supplied on the command line is
# resolved (or prompted for) inside Get-InteractiveParameters.
[CmdletBinding()]
param(
    [string]$Location = "eastus2",         # Azure region; may be overridden interactively
    [string]$AdminGroupObjectId,           # Entra group granted cluster-admin (prompted if empty)
    [string]$SubscriptionId,               # target subscription (auto-selected if only one)
    [string]$AuthorizedIpRange,            # IP allowed to reach the API server (auto-detected if empty)
    [bool]$EnableDefender = $false         # Defender for Containers costs extra; off by default
)

# Stop the whole deployment on the first unhandled error so we don't press on
# after, say, a failed Bicep deployment. The main try/catch below turns that into
# a clean message + non-zero exit.
$ErrorActionPreference = "Stop"

# ── Helper Functions ────────────────────────────────────────────────────────

function Write-ColoredOutput {
    # Thin wrapper over Write-Host that defaults the color to White. Every status
    # line in this script goes through here for consistent, readable output.
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Get-PublicIPAddress {
    # Best-effort detection of the caller's public IP, used to lock the AKS API
    # server down to just this machine. Returns the IP string, or $null if it
    # couldn't be determined (caller then prompts for it).
    try {
        # api.ipify.org echoes back the caller's egress IP as plain text.
        $ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        # Sanity-check it really is a dotted-quad IPv4 before trusting it — each
        # octet must be 0-255. Guards against an error page sneaking through.
        if ($ip -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            return $ip
        }
        throw "Invalid IP format"
    }
    catch {
        # Network blip, timeout, or bad format — degrade gracefully to a prompt.
        Write-ColoredOutput "  Could not auto-detect IP." "Yellow"
        return $null
    }
}

function Test-Prerequisites {
    # Fail fast if the local toolchain or the Bicep templates aren't in place.
    # Better to stop here with a clear install hint than mid-deploy.
    Write-ColoredOutput "[*] Checking prerequisites..." "Yellow"

    # Az.Accounts is the core Azure PowerShell module (Connect-AzAccount etc.).
    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-ColoredOutput "[!] Azure PowerShell module not found. Install with:" "Red"
        Write-ColoredOutput "    Install-Module -Name Az -Repository PSGallery -Force" "White"
        exit 1
    }
    Write-ColoredOutput "  [+] Azure PowerShell module found." "Green"

    # Bicep is REQUIRED — it compiles the .bicep templates the deploy relies on.
    # Missing it is fatal.
    try {
        $bicepVersion = & bicep --version 2>&1
        Write-ColoredOutput "  [+] Bicep CLI: $bicepVersion" "Green"
    } catch {
        Write-ColoredOutput "[!] Bicep CLI not found. Install with:" "Red"
        Write-ColoredOutput "    winget install -e --id Microsoft.Bicep" "White"
        exit 1
    }

    # kubectl is only needed AFTER the cluster exists (to apply manifests), so its
    # absence is a warning, not a hard stop.
    try {
        $kubectlVersion = & kubectl version --client 2>&1 | Select-Object -First 1
        Write-ColoredOutput "  [+] kubectl: $kubectlVersion" "Green"
    } catch {
        Write-ColoredOutput "  [!] kubectl not found. Will be needed post-deployment." "Yellow"
    }

    # Both templates must sit next to this script ($PSScriptRoot = the script's
    # own directory). Their absence means a broken checkout — fail now.
    if (-not (Test-Path (Join-Path $PSScriptRoot "main.bicep"))) {
        Write-ColoredOutput "[!] main.bicep not found in infrastructure directory." "Red"
        exit 1
    }
    if (-not (Test-Path (Join-Path $PSScriptRoot "main_subscription.bicep"))) {
        Write-ColoredOutput "[!] main_subscription.bicep not found in infrastructure directory." "Red"
        exit 1
    }
    Write-ColoredOutput "  [+] Bicep templates found." "Green"
}

function Initialize-AzureContext {
    # Ensure we're authenticated and pointed at the intended subscription.
    param([string]$SubscriptionId)

    Write-ColoredOutput "`n[*] Authenticating to Azure..." "Yellow"

    # Reuse an existing session if one is cached; only prompt for interactive
    # login when there's none.
    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Connect-AzAccount
        $context = Get-AzContext
    }

    Write-ColoredOutput "  [+] Authenticated as: $($context.Account.Id)" "Green"
    Write-ColoredOutput "  [+] Tenant: $($context.Tenant.Id)" "Green"

    # Switch context only if a specific subscription was requested and it isn't
    # already the active one (avoids a redundant Set-AzContext call).
    if ($SubscriptionId -and (Get-AzContext).Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
}

function Get-InteractiveParameters {
    # Resolve every deployment input: use what was passed on the command line, and
    # for anything missing either auto-detect it or prompt the user. Returns a
    # hashtable of the fully-resolved parameters consumed by the rest of the run.
    param(
        [string]$Location,
        [string]$AdminGroupObjectId,
        [string]$SubscriptionId,
        [string]$AuthorizedIpRange,
        [bool]$EnableDefender
    )

    Write-ColoredOutput "`n[*] Collecting deployment parameters..." "Yellow"

    # -- Subscription -- auto-pick when there's exactly one enabled sub; otherwise
    # present a numbered menu and let the user choose.
    if (-not $SubscriptionId) {
        $subs = Get-AzSubscription | Where-Object { $_.State -eq 'Enabled' }
        if ($subs.Count -eq 1) {
            $SubscriptionId = $subs[0].Id
            Write-ColoredOutput "  [+] Using subscription: $($subs[0].Name) ($SubscriptionId)" "Green"
        } else {
            Write-ColoredOutput "`n  Available subscriptions:" "Cyan"
            for ($i = 0; $i -lt $subs.Count; $i++) {
                Write-ColoredOutput "    [$i] $($subs[$i].Name) ($($subs[$i].Id))" "White"
            }
            $selection = Read-Host "  Select subscription (0-$($subs.Count - 1))"
            $SubscriptionId = $subs[$selection].Id
        }
    }
    # Make the chosen subscription active for all subsequent Az calls.
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    # -- Unique lab suffix -- 6 random lowercase-alphanumeric chars, built from the
    # ASCII ranges a-z (97..122) and 0-9 (48..57). Keeps resource names globally
    # unique-ish so repeated lab deploys don't collide (ACR/Key Vault names are
    # global). Every resource in this run shares this suffix.
    $labSuffix = -join ((97..122) + (48..57) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $ResourceGroupName = "aks-adversary-lab-$labSuffix"
    $NamePrefix = "lab$labSuffix"

    Write-ColoredOutput "  [+] Lab ID: $labSuffix" "Green"
    Write-ColoredOutput "  [+] Resource Group: $ResourceGroupName" "Green"
    Write-ColoredOutput "  [+] Resource Prefix: $NamePrefix" "Green"

    # -- Admin group -- AKS is deployed with Entra (AAD) RBAC, so cluster-admin is
    # granted to an Entra security group rather than individual users. Required, so
    # prompt if not supplied.
    if (-not $AdminGroupObjectId) {
        Write-ColoredOutput "`n  [!] You need an Entra ID security group for AKS cluster-admin access." "Yellow"
        Write-ColoredOutput "      Create one in Entra ID > Groups, then provide the Object ID." "White"
        $AdminGroupObjectId = Read-Host "  Entra ID Admin Group Object ID"
    }

    # -- Authorized IP -- the AKS API server is locked to an allowlist; default it
    # to this machine's public IP. Offer the detected value, allow override, and
    # fall back to a manual prompt if detection failed.
    if (-not $AuthorizedIpRange) {
        Write-ColoredOutput "`n  [*] Detecting your public IP..." "Yellow"
        $AuthorizedIpRange = Get-PublicIPAddress
        if ($null -ne $AuthorizedIpRange) {
            Write-ColoredOutput "  [+] Detected IP: $AuthorizedIpRange" "Green"
            $confirm = Read-Host "  Use this IP for API server access? (Y/n)"
            if ($confirm -eq 'n' -or $confirm -eq 'N') {
                $AuthorizedIpRange = Read-Host "  Enter your public IP address"
            }
        } else {
            $AuthorizedIpRange = Read-Host "  Enter your public IP address"
        }
    }

    # -- Region -- present a menu when no explicit non-default region was passed.
    # Note: because the param default is already "eastus2", we can't distinguish
    # "user typed eastus2" from "user typed nothing", so both re-open the menu.
    $validLocations = @("eastus", "eastus2", "westus2", "westus3", "centralus", "northeurope", "westeurope", "uksouth", "southeastasia", "australiaeast")
    if (-not $Location -or $Location -eq "eastus2") {
        Write-ColoredOutput "`n  Select deployment region:" "Cyan"
        for ($i = 0; $i -lt $validLocations.Count; $i++) {
            $default = if ($validLocations[$i] -eq "eastus2") { " (default)" } else { "" }
            Write-ColoredOutput "    [$i] $($validLocations[$i])$default" "White"
        }
        $locSelection = Read-Host "  Select region (0-$($validLocations.Count - 1)) [1 for eastus2]"
        # Empty input -> index 1, which is eastus2 (the default).
        if ([string]::IsNullOrWhiteSpace($locSelection)) { $locSelection = 1 }
        $Location = $validLocations[[int]$locSelection]
    }
    Write-ColoredOutput "  [+] Region: $Location" "Green"

    # Return everything the pipeline needs as a single hashtable.
    return @{
        SubscriptionId     = $SubscriptionId
        ResourceGroupName  = $ResourceGroupName
        NamePrefix         = $NamePrefix
        LabSuffix          = $labSuffix
        Location           = $Location
        AdminGroupObjectId = $AdminGroupObjectId
        AuthorizedIpRange  = $AuthorizedIpRange
        EnableDefender     = $EnableDefender
    }
}

function Show-ConfigurationSummary {
    # Print the resolved plan and the cost warning, then require an explicit y/n.
    # This is the last stop before any billable resources are created.
    param([hashtable]$Params)

    Write-ColoredOutput "`n=== Configuration Summary ===" "Cyan"
    Write-ColoredOutput "  Subscription:    $($Params.SubscriptionId)" "White"
    Write-ColoredOutput "  Resource Group:  $($Params.ResourceGroupName)" "White"
    Write-ColoredOutput "  Location:        $($Params.Location)" "White"
    Write-ColoredOutput "  Name Prefix:     $($Params.NamePrefix) (auto-generated)" "White"
    Write-ColoredOutput "  Authorized IP:   $($Params.AuthorizedIpRange)" "White"
    Write-ColoredOutput "  Admin Group:     $($Params.AdminGroupObjectId)" "White"
    Write-ColoredOutput "  Defender:        $(if($Params.EnableDefender){"Enabled (~`$56/mo)"}else{"Disabled (using Falco only)"})" "White"

    Write-ColoredOutput "`n[!] This will create Azure resources that incur costs." "Yellow"
    Write-ColoredOutput "    Estimated: ~`$150-200/month (AKS + logging + Defender)" "Yellow"

    # Explicit opt-in gate. Anything other than 'n'/'N' proceeds; a cancel exits 0
    # (a clean, deliberate no-op, not an error).
    $proceed = Read-Host "`nProceed with deployment? (Y/n)"
    if ($proceed -eq 'n' -or $proceed -eq 'N') {
        Write-ColoredOutput "Deployment cancelled." "Red"
        exit 0
    }
}

function New-LabResourceGroup {
    # Create (or overwrite, via -Force) the lab resource group, tagged so it's
    # easy to identify and clean up later.
    param([string]$Name, [string]$Location)

    Write-ColoredOutput "`n[*] Creating resource group: $Name..." "Yellow"
    # -Force makes this idempotent (no prompt if it already exists). Tags label the
    # RG as a disposable security lab.
    New-AzResourceGroup -Name $Name -Location $Location -Force -Tag @{
        Environment = "SecurityLab"
        Project     = "AKS-Adversary-Lab"
        Purpose     = "MITRE-ATT&CK-Containers"
    } | Out-Null
    Write-ColoredOutput "  [+] Resource group created." "Green"
}

function Deploy-Infrastructure {
    # The main event: deploy main.bicep at RESOURCE GROUP scope. This provisions
    # the bulk of the lab (network, logging, registry, secrets, the AKS cluster,
    # diagnostics, Sentinel, policy). Takes 8-15 minutes.
    param([hashtable]$Params)

    Write-ColoredOutput "`n[*] Deploying AKS Adversary Lab infrastructure (8-15 minutes)..." "Yellow"
    Write-ColoredOutput "    VNet, Log Analytics, ACR, Key Vault, AKS Cluster," "White"
    Write-ColoredOutput "    Diagnostics, Container Insights, Sentinel, Azure Policy" "White"

    # Timestamped deployment name so each run shows as a distinct entry under the
    # RG's Deployments history in the portal.
    $deploymentName = "aks-adversary-lab-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

    # Each -paramName here maps to a parameter declared in main.bicep. logRetention
    # 90 days, Azure Policy + Sentinel solutions on; Defender toggled per -EnableDefender.
    # -Verbose streams provisioning progress; -ErrorAction Stop turns any failure fatal.
    $rgDeployment = New-AzResourceGroupDeployment `
        -Name $deploymentName `
        -ResourceGroupName $Params.ResourceGroupName `
        -TemplateFile (Join-Path $PSScriptRoot "main.bicep") `
        -namePrefix $Params.NamePrefix `
        -adminGroupObjectId $Params.AdminGroupObjectId `
        -authorizedIpRange $Params.AuthorizedIpRange `
        -logRetentionDays 90 `
        -enableDefender $Params.EnableDefender `
        -enableAzurePolicy $true `
        -enableSentinelSolutions $true `
        -ErrorAction Stop `
        -Verbose

    # Belt-and-suspenders: even with -ErrorAction Stop, verify the reported state.
    if ($rgDeployment.ProvisioningState -ne 'Succeeded') {
        throw "Resource group deployment finished with state: $($rgDeployment.ProvisioningState)"
    }

    Write-ColoredOutput "  [+] Infrastructure deployment succeeded!" "Green"
    # Return both the deployment object (for its Outputs) and its name (reused to
    # name the subscription-level deployment).
    return @{ Deployment = $rgDeployment; DeploymentName = $deploymentName }
}

function Deploy-SubscriptionResources {
    # Deploy main_subscription.bicep at SUBSCRIPTION scope for the handful of
    # resources that can't live inside a resource group (Defender plans, subscription
    # Activity-log routing). Wrapped in try/catch because this is NON-CRITICAL: a
    # failure here shouldn't undo a successful cluster deploy.
    param([hashtable]$Params, $RgDeployment)

    Write-ColoredOutput "`n[*] Deploying subscription-level resources (Defender, Activity logs)..." "Yellow"

    try {
        # Subscription deployments require a -Location (there's no RG to inherit one
        # from). We feed it the workspace ID output by the RG deployment so Defender
        # data lands in the same Log Analytics workspace.
        New-AzSubscriptionDeployment `
            -Name "aks-lab-sub-$($Params.DeploymentName)" `
            -Location $Params.Location `
            -TemplateFile (Join-Path $PSScriptRoot "main_subscription.bicep") `
            -TemplateParameterObject @{
                location                   = $Params.Location
                logAnalyticsWorkspaceId    = $RgDeployment.Outputs.logAnalyticsWorkspaceId.Value
                enableDefenderForContainers = $Params.EnableDefender
                enableDefenderForKeyVault   = $Params.EnableDefender
            } `
            -Verbose | Out-Null

        Write-ColoredOutput "  [+] Subscription deployment succeeded!" "Green"
    } catch {
        # Often a permissions gap at subscription scope. Warn and continue — the
        # user can enable Defender by hand later.
        Write-ColoredOutput "  [!] Subscription deployment failed (non-critical): $_" "Yellow"
        Write-ColoredOutput "      You may need to enable Defender for Containers manually." "White"
    }
}

function Set-KubectlAccess {
    # Merge the new cluster's credentials into the local kubeconfig so kubectl (and
    # the manifest step below) can talk to it. Uses the Azure CLI's helper.
    param([string]$ResourceGroupName, [string]$ClusterName)

    Write-ColoredOutput "`n[*] Configuring kubectl access..." "Yellow"

    # If the Bicep didn't surface a cluster name, we can't fetch credentials.
    if ([string]::IsNullOrEmpty($ClusterName)) {
        Write-ColoredOutput "  [!] Cluster name not available in outputs." "Yellow"
        return
    }

    # Prefer automatic wiring via `az`; fall back to printing the manual command.
    if (Get-Command az -ErrorAction SilentlyContinue) {
        try {
            # --overwrite-existing replaces any stale context of the same name.
            az aks get-credentials --resource-group $ResourceGroupName --name $ClusterName --overwrite-existing 2>&1
            Write-ColoredOutput "  [+] kubectl configured for cluster: $ClusterName" "Green"
        } catch {
            Write-ColoredOutput "  [!] Could not auto-configure kubectl. Run manually:" "Yellow"
            Write-ColoredOutput "      az aks get-credentials --resource-group $ResourceGroupName --name $ClusterName" "White"
        }
    } else {
        Write-ColoredOutput "  [!] Azure CLI (az) not found. Run manually:" "Yellow"
        Write-ColoredOutput "      az aks get-credentials --resource-group $ResourceGroupName --name $ClusterName" "White"
    }
}

function Install-KubernetesManifests {
    # Apply the in-cluster configuration: logging schema, namespaces, network
    # policies, RBAC, and the deliberately-vulnerable victim apps. Order matters —
    # namespaces must exist before the objects placed inside them.

    # Manifests live in the repo, one directory above infrastructure/.
    $repoRoot = Split-Path $PSScriptRoot -Parent

    # No kubectl -> can't apply anything; tell the user and bail (non-fatal).
    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Write-ColoredOutput "`n[!] kubectl not found. Apply manifests manually after installing kubectl." "Yellow"
        return
    }

    Write-ColoredOutput "`n[*] Applying Kubernetes manifests..." "Yellow"

    # Ordered list of manifests with human-readable descriptions.
    $manifests = @(
        @{ Path = "$repoRoot/kubernetes/monitoring/container-insights-config.yaml"; Desc = "Container Insights v2 schema (ContainerLogV2)" },
        @{ Path = "$repoRoot/kubernetes/namespaces/namespaces.yaml";               Desc = "Namespaces (attacker, victim, monitoring, security-tools)" },
        @{ Path = "$repoRoot/kubernetes/network-policies/victim-netpol.yaml";      Desc = "Victim namespace network policies" },
        @{ Path = "$repoRoot/kubernetes/network-policies/attacker-netpol.yaml";    Desc = "Attacker namespace network policies" },
        @{ Path = "$repoRoot/kubernetes/network-policies/monitoring-netpol.yaml";  Desc = "Monitoring namespace network policies" },
        @{ Path = "$repoRoot/kubernetes/rbac/rbac.yaml";                           Desc = "RBAC roles and bindings" },
        @{ Path = "$repoRoot/kubernetes/victim-apps/victim-apps.yaml";             Desc = "Victim applications (DVWA, vulnerable API)" }
    )

    # Apply each manifest that exists, reporting success/failure per file. A single
    # failure is a warning, not a stop — we still try the rest.
    foreach ($manifest in $manifests) {
        if (Test-Path $manifest.Path) {
            Write-ColoredOutput "  Applying: $($manifest.Desc)..." "White"
            # 2>&1 folds kubectl's stderr into $result; $LASTEXITCODE reflects the
            # external command's exit status (0 = applied cleanly).
            $result = kubectl apply -f $manifest.Path 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-ColoredOutput "  [+] Applied." "Green"
            } else {
                Write-ColoredOutput "  [!] Failed: $result" "Yellow"
            }
        } else {
            Write-ColoredOutput "  [!] Not found: $($manifest.Path)" "Yellow"
        }
    }
}

function Show-DeploymentSummary {
    # Print the key resource names from the Bicep outputs plus the manual
    # post-deploy steps (Falco, red-team tools, validation, teardown).
    param([hashtable]$Params, $RgDeployment)

    $repoRoot = Split-Path $PSScriptRoot -Parent

    # Read each output defensively: if the Bicep didn't emit it, fall back to a
    # sensible default/placeholder rather than erroring. clusterName defaults to
    # the conventional "<prefix>-aks" naming.
    $outCluster = if ($RgDeployment.Outputs.clusterName)               { $RgDeployment.Outputs.clusterName.Value }               else { "$($Params.NamePrefix)-aks" }
    $outFqdn    = if ($RgDeployment.Outputs.clusterFqdn)               { $RgDeployment.Outputs.clusterFqdn.Value }               else { "(not available)" }
    $outAcr     = if ($RgDeployment.Outputs.acrLoginServer)            { $RgDeployment.Outputs.acrLoginServer.Value }            else { "(not available)" }
    $outLaw     = if ($RgDeployment.Outputs.logAnalyticsWorkspaceName) { $RgDeployment.Outputs.logAnalyticsWorkspaceName.Value } else { "(not available)" }
    $outKv      = if ($RgDeployment.Outputs.keyVaultName)              { $RgDeployment.Outputs.keyVaultName.Value }              else { "(not available)" }

    Write-ColoredOutput "`n=== Deployment Complete ===" "Green"
    Write-ColoredOutput "  Cluster:        $outCluster" "White"
    Write-ColoredOutput "  FQDN:           $outFqdn" "White"
    Write-ColoredOutput "  ACR:            $outAcr" "White"
    Write-ColoredOutput "  Log Analytics:  $outLaw" "White"
    Write-ColoredOutput "  Key Vault:      $outKv" "White"

    Write-ColoredOutput "`n=== Post-Deployment Steps ===" "Yellow"
    Write-ColoredOutput "  1. Deploy Falco:" "White"
    Write-ColoredOutput "     helm repo add falcosecurity https://falcosecurity.github.io/charts" "Cyan"
    Write-ColoredOutput "     helm dependency update $repoRoot/helm/falco && helm install falco $repoRoot/helm/falco -n monitoring" "Cyan"
    Write-ColoredOutput ""
    Write-ColoredOutput "  2. Deploy red team tools:" "White"
    Write-ColoredOutput "     kubectl apply -f $repoRoot/kubernetes/red-team/red-team-tools.yaml" "Cyan"
    Write-ColoredOutput ""
    Write-ColoredOutput "  3. Wait 15-30 minutes for Defender and log ingestion" "White"
    Write-ColoredOutput ""
    Write-ColoredOutput "  4. Validate with KQL:" "White"
    Write-ColoredOutput "     ContainerLogV2 | take 5" "Cyan"
    Write-ColoredOutput ""
    Write-ColoredOutput "[!] Delete when done: Remove-AzResourceGroup -Name $($Params.ResourceGroupName) -Force" "Yellow"
}

# ── Main Execution ──────────────────────────────────────────────────────────
# Orchestrates the whole deploy in order. The single try/catch means ANY failure
# in any step lands in one place: a red error + hint + non-zero exit. The finally
# block always runs, even on success or Ctrl-C.

try {
    Write-ColoredOutput "`n=== AKS Adversary Lab ===" "Cyan"

    # 1. Verify local tooling and templates before doing anything billable.
    Test-Prerequisites

    # 2. Resolve/prompt every input into a single $params hashtable.
    $params = Get-InteractiveParameters `
        -Location $Location `
        -AdminGroupObjectId $AdminGroupObjectId `
        -SubscriptionId $SubscriptionId `
        -AuthorizedIpRange $AuthorizedIpRange `
        -EnableDefender $EnableDefender

    # 3. Log in / select the subscription the user chose.
    Initialize-AzureContext -SubscriptionId $params.SubscriptionId

    # 4. Last confirmation before spending money.
    Show-ConfigurationSummary -Params $params

    # 5. Create the resource group that will hold everything.
    New-LabResourceGroup -Name $params.ResourceGroupName -Location $params.Location

    # 6. Deploy the RG-scoped stack (the long step). Unpack the returned object.
    $infraResult = Deploy-Infrastructure -Params $params
    $rgDeployment = $infraResult.Deployment

    # 7. Deploy the subscription-scoped extras. We pass a small purpose-built
    #    hashtable (not the full $params) carrying just what this step needs,
    #    including the RG deployment name so the two deployments are correlated.
    Deploy-SubscriptionResources -Params @{
        Location       = $params.Location
        DeploymentName = $infraResult.DeploymentName
        EnableDefender = $params.EnableDefender
    } -RgDeployment $rgDeployment

    # 8. Wire up kubectl. Resolve the cluster name from outputs, or fall back to
    #    the conventional "<prefix>-aks" name.
    $clusterName = if ($rgDeployment.Outputs.clusterName) { $rgDeployment.Outputs.clusterName.Value } else { "$($params.NamePrefix)-aks" }
    Set-KubectlAccess -ResourceGroupName $params.ResourceGroupName -ClusterName $clusterName

    # 9. Apply the in-cluster manifests.
    Install-KubernetesManifests

    # 10. Print outputs + next steps.
    Show-DeploymentSummary -Params $params -RgDeployment $rgDeployment

    Write-ColoredOutput "`nDeployment completed successfully!" "Green"
}
catch {
    # Any thrown error (or -ErrorAction Stop failure) funnels here.
    Write-ColoredOutput "`n[!] Deployment failed: $($_.Exception.Message)" "Red"
    Write-ColoredOutput "    Check Azure Portal > Resource Group > Deployments for details." "Yellow"
    exit 1
}
finally {
    # Housekeeping that runs no matter how the try block ended: drop references to
    # the (potentially large) deployment objects and nudge the GC. Note this does
    # NOT delete any Azure resources — teardown is a manual Remove-AzResourceGroup
    # (see the reminder printed by Show-DeploymentSummary).
    $params = $null
    $infraResult = $null
    $rgDeployment = $null
    [System.GC]::Collect()
}
