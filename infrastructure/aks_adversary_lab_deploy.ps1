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
      2. Initialize-AzureContext   — log in before listing subscriptions
      3. Get-DeploymentParameters — resolve/prompt for every deploy input
      4. Initialize-AzureContext   — select the resolved subscription
      5. Test-PrecreatedLabResourceGroup — verify the bootstrap-created RG
      6. Show-ConfigurationSummary — print the plan and get a cost-aware y/n
      7. Test-PolicyInitiativeBootstrap — confirm subscription policy bootstrap
      8. Deploy-Infrastructure     — main.bicep (RG-scoped: AKS + logging + ...)
      9. Deploy-SubscriptionResources — main_subscription.bicep (Defender, etc.)
     10. Set-KubectlAccess         — pull cluster credentials for kubectl
     11. Install-KubernetesManifests — apply namespaces, netpol, RBAC, victims
     12. Show-DeploymentSummary    — outputs + copy/paste post-deploy steps

    Two Bicep templates are used because Azure deployments are scoped: most
    resources live inside the resource group (main.bicep), but a few — Defender
    plans, subscription Activity-log routing — must be deployed at SUBSCRIPTION
    scope (main_subscription.bicep).

.PARAMETER Location
    Azure region for deployment. Prompted interactively when omitted.

.PARAMETER NamePrefix
    Lowercase 3-15-character resource prefix. The script derives the required
    pre-created resource group as rg-<NamePrefix>-aks-lab.

.PARAMETER ResourceGroupName
    Optional explicit form of the derived resource group name. When specified,
    it must exactly equal rg-<NamePrefix>-aks-lab.

.PARAMETER AdminGroupObjectId
    Entra ID group Object ID for AKS cluster-admin access.

.PARAMETER SubscriptionId
    Azure subscription ID.

.PARAMETER AuthorizedIpRange
    Your public IPv4 CIDR for API server authorized access. Prompted with a
    detected /32 suggestion when omitted.

.PARAMETER NonInteractive
    Requires SubscriptionId, NamePrefix, Location, AdminGroupObjectId, and
    AuthorizedIpRange to be supplied. The script does not prompt or auto-detect
    values in this mode. Also requires -Approve before any deployment.

.PARAMETER Approve
    Explicitly permits a -NonInteractive run to proceed after printing the cost
    summary. Interactive runs ignore this parameter and ask for confirmation.

.EXAMPLE
    ./infrastructure/aks_adversary_lab_deploy.ps1

.EXAMPLE
    ./infrastructure/aks_adversary_lab_deploy.ps1 `
        -SubscriptionId "<subscription-id>" `
        -NamePrefix "labdemo" `
        -Location "eastus2" `
        -AdminGroupObjectId "<entra-group-object-id>" `
        -AuthorizedIpRange "203.0.113.10/32" `
        -Approve `
        -NonInteractive
#>

# All deployment values can be supplied for automation. Interactive runs prompt
# for omitted required values after Azure authentication is available.
[CmdletBinding()]
param(
    [string]$Location,
    [string]$NamePrefix,
    [string]$ResourceGroupName,
    [string]$AdminGroupObjectId,
    [string]$SubscriptionId,
    [string]$AuthorizedIpRange,
    [bool]$EnableDefender = $false,
    [switch]$Approve,
    [switch]$NonInteractive
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
            return "$ip/32"
        }
        throw "Invalid IP format"
    }
    catch {
        # Network blip, timeout, or bad format — degrade gracefully to a prompt.
        Write-ColoredOutput "  Could not auto-detect IP." "Yellow"
        return $null
    }
}

function Test-PublicIpv4Cidr {
    param(
        [Parameter(Mandatory)]
        [string]$Value
    )

    if ($Value -notmatch '^(?<address>(?:\d{1,3}\.){3}\d{1,3})/(?<prefix>\d{1,2})$') {
        return $false
    }

    $octets = $Matches.address.Split('.') | ForEach-Object { [int]$_ }
    $prefixLength = [int]$Matches.prefix
    if (($octets | Where-Object { $_ -gt 255 }).Count -gt 0 -or $prefixLength -gt 32) {
        return $false
    }

    $first = $octets[0]
    $second = $octets[1]
    return -not (
        $first -eq 0 -or
        $first -eq 10 -or
        ($first -eq 172 -and $second -ge 16 -and $second -le 31) -or
        ($first -eq 192 -and $second -eq 168) -or
        $first -eq 127 -or
        ($first -eq 169 -and $second -eq 254) -or
        ($first -ge 224 -and $first -le 239)
    )
}

function Test-RequiredValue {
    param(
        [string]$Name,
        [string]$Value,
        [bool]$NonInteractive
    )

    if ($NonInteractive -and [string]::IsNullOrWhiteSpace($Value)) {
        throw "-NonInteractive requires -$Name."
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

function Get-DeploymentParameters {
    # Resolve every deployment input. Interactive runs guide first-time operators;
    # noninteractive runs require explicit values so automation never blocks.
    param(
        [string]$Location,
        [string]$NamePrefix,
        [string]$ResourceGroupName,
        [string]$AdminGroupObjectId,
        [string]$SubscriptionId,
        [string]$AuthorizedIpRange,
        [bool]$EnableDefender,
        [bool]$NonInteractive
    )

    Write-ColoredOutput "`n[*] Collecting deployment parameters..." "Yellow"

    Test-RequiredValue -Name "SubscriptionId" -Value $SubscriptionId -NonInteractive $NonInteractive
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
        do {
            $selection = Read-Host "  Select subscription (0-$($subs.Count - 1))"
        } until ($selection -match '^\d+$' -and [int]$selection -lt $subs.Count)
        $SubscriptionId = $subs[[int]$selection].Id
        }
    }

    Test-RequiredValue -Name "NamePrefix" -Value $NamePrefix -NonInteractive $NonInteractive
    do {
        if (-not $NamePrefix) {
        Write-ColoredOutput "`n  [!] Choose a lowercase 3-15-character prefix. The required resource group is rg-<prefix>-aks-lab." "Yellow"
        $NamePrefix = Read-Host "  Name prefix"
        }
        if ($NamePrefix -notmatch '^[a-z][a-z0-9]{2,14}$') {
        if ($NonInteractive) {
            throw "-NamePrefix must be 3-15 lowercase alphanumeric characters starting with a letter."
        }
        Write-ColoredOutput "  [!] Name prefix must be 3-15 lowercase alphanumeric characters starting with a letter." "Red"
        $NamePrefix = $null
        }
    } until ($NamePrefix)

    $derivedResourceGroupName = "rg-$NamePrefix-aks-lab"
    if ($ResourceGroupName -and $ResourceGroupName -cne $derivedResourceGroupName) {
        throw "-ResourceGroupName must equal the derived lab group '$derivedResourceGroupName'."
    }
    $ResourceGroupName = $derivedResourceGroupName
    Write-ColoredOutput "  [+] Required pre-created resource group: $ResourceGroupName" "Green"

    Test-RequiredValue -Name "AdminGroupObjectId" -Value $AdminGroupObjectId -NonInteractive $NonInteractive
    do {
        if (-not $AdminGroupObjectId) {
        Write-ColoredOutput "`n  [!] Provide the Object ID of the Entra security group that will receive AKS cluster-admin." "Yellow"
        $AdminGroupObjectId = Read-Host "  Entra ID Admin Group Object ID"
        }
        if ($AdminGroupObjectId -notmatch '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        if ($NonInteractive) {
            throw "-AdminGroupObjectId must be an Entra object-ID UUID."
        }
        Write-ColoredOutput "  [!] Admin group Object ID must be an Entra object-ID UUID." "Red"
        $AdminGroupObjectId = $null
        }
    } until ($AdminGroupObjectId)

    Test-RequiredValue -Name "AuthorizedIpRange" -Value $AuthorizedIpRange -NonInteractive $NonInteractive
    if (-not $AuthorizedIpRange) {
        Write-ColoredOutput "`n  [*] Detecting your public IP..." "Yellow"
        $AuthorizedIpRange = Get-PublicIPAddress
        if ($null -ne $AuthorizedIpRange) {
        Write-ColoredOutput "  [+] Detected public IPv4 CIDR: $AuthorizedIpRange" "Green"
        $confirm = Read-Host "  Use this CIDR for API server access? (Y/n)"
        if ($confirm -eq 'n' -or $confirm -eq 'N') {
            $AuthorizedIpRange = $null
        }
        }
    }

    do {
        if (-not $AuthorizedIpRange) {
        $AuthorizedIpRange = Read-Host "  Enter a public IPv4 CIDR (for example, 203.0.113.10/32)"
        }
        if (-not (Test-PublicIpv4Cidr -Value $AuthorizedIpRange)) {
        if ($NonInteractive) {
            throw "-AuthorizedIpRange must be a public IPv4 CIDR."
        }
        Write-ColoredOutput "  [!] Authorized IP range must be a public IPv4 CIDR and cannot be private, loopback, link-local, multicast, or reserved." "Red"
        $AuthorizedIpRange = $null
        }
    } until ($AuthorizedIpRange)

    $validLocations = @("eastus", "eastus2", "westus2", "centralus", "uksouth", "westeurope")
    Test-RequiredValue -Name "Location" -Value $Location -NonInteractive $NonInteractive
    do {
        if (-not $Location) {
        Write-ColoredOutput "`n  Select deployment region:" "Cyan"
        for ($i = 0; $i -lt $validLocations.Count; $i++) {
            $default = if ($validLocations[$i] -eq "eastus2") { " (default)" } else { "" }
            Write-ColoredOutput "    [$i] $($validLocations[$i])$default" "White"
        }
        $locSelection = Read-Host "  Select region (0-$($validLocations.Count - 1)) [1 for eastus2]"
        if ([string]::IsNullOrWhiteSpace($locSelection)) { $locSelection = 1 }
        if ($locSelection -match '^\d+$' -and [int]$locSelection -lt $validLocations.Count) {
            $Location = $validLocations[[int]$locSelection]
        }
        }
        if ($Location -notin $validLocations) {
        if ($NonInteractive) {
            throw "-Location must be one of: $($validLocations -join ', ')."
        }
        Write-ColoredOutput "  [!] Select one of: $($validLocations -join ', ')." "Red"
        $Location = $null
        }
    } until ($Location)
    Write-ColoredOutput "  [+] Region: $Location" "Green"

    return @{
        SubscriptionId     = $SubscriptionId
        ResourceGroupName  = $ResourceGroupName
        NamePrefix         = $NamePrefix
        Location           = $Location
        AdminGroupObjectId = $AdminGroupObjectId
        AuthorizedIpRange  = $AuthorizedIpRange
        EnableDefender     = $EnableDefender
    }
}

function Show-ConfigurationSummary {
    # Print the resolved plan and the cost warning, then require an explicit y/n.
    # This is the last stop before any billable resources are created.
    param(
        [hashtable]$Params,
        [bool]$NonInteractive,
        [bool]$Approve
    )

    Write-ColoredOutput "`n=== Configuration Summary ===" "Cyan"
    Write-ColoredOutput "  Subscription:    $($Params.SubscriptionId)" "White"
    Write-ColoredOutput "  Resource Group:  $($Params.ResourceGroupName)" "White"
    Write-ColoredOutput "  Location:        $($Params.Location)" "White"
    Write-ColoredOutput "  Name Prefix:     $($Params.NamePrefix)" "White"
    Write-ColoredOutput "  Authorized IP:   $($Params.AuthorizedIpRange)" "White"
    Write-ColoredOutput "  Admin Group:     $($Params.AdminGroupObjectId)" "White"
    Write-ColoredOutput "  Defender:        $(if($Params.EnableDefender){"Enabled (~`$56/mo)"}else{"Disabled (using Falco only)"})" "White"

    Write-ColoredOutput "`n[!] This will create Azure resources that incur costs." "Yellow"
    Write-ColoredOutput "    Estimated: ~`$150-200/month (AKS + logging + Defender)" "Yellow"

    if ($NonInteractive) {
        if (-not $Approve) {
            throw "-NonInteractive requires -Approve before creating Azure resources."
        }
        Write-ColoredOutput "  [+] Noninteractive deployment explicitly approved." "Green"
        return
    }

    # Explicit opt-in gate. Anything other than 'n'/'N' proceeds; a cancel exits 0
    # (a clean, deliberate no-op, not an error).
    $proceed = Read-Host "`nProceed with deployment? (Y/n)"
    if ($proceed -eq 'n' -or $proceed -eq 'N') {
        Write-ColoredOutput "Deployment cancelled." "Red"
        exit 0
    }
}

function Test-PrecreatedLabResourceGroup {
    param(
        [string]$Name,
        [string]$Location
    )

    $resourceGroup = Get-AzResourceGroup -Name $Name -ErrorAction SilentlyContinue
    if (-not $resourceGroup) {
        throw "Required lab resource group '$Name' does not exist. A bootstrap administrator must create it before local deployment."
    }
    if ($resourceGroup.Location -ine $Location) {
        throw "Resource group '$Name' is in '$($resourceGroup.Location)', not requested location '$Location'. Use the pre-created resource group's location."
    }

    Write-ColoredOutput "  [+] Pre-created resource group verified: $Name" "Green"
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

function Test-PolicyInitiativeBootstrap {
    # The initiative is subscription-scoped and intentionally provisioned by the
    # bootstrap administrator, not by this RG-scoped lab deployment.
    $initiative = Get-AzPolicySetDefinition `
        -Name "aks-adversary-lab-logging-initiative" `
        -ErrorAction SilentlyContinue
    if (-not $initiative) {
        throw "Policy initiative 'aks-adversary-lab-logging-initiative' is missing. Run tools/bootstrap-policy-definitions.ps1 as the bootstrap administrator before deploying the lab."
    }

    Write-ColoredOutput "  [+] Bootstrap policy initiative verified." "Green"
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

    # 2. Authenticate before an interactive run lists available subscriptions.
    Initialize-AzureContext -SubscriptionId $SubscriptionId

    # 3. Resolve/prompt every input into a single $params hashtable.
    $params = Get-DeploymentParameters `
        -Location $Location `
        -NamePrefix $NamePrefix `
        -ResourceGroupName $ResourceGroupName `
        -AdminGroupObjectId $AdminGroupObjectId `
        -SubscriptionId $SubscriptionId `
        -AuthorizedIpRange $AuthorizedIpRange `
        -EnableDefender $EnableDefender `
        -NonInteractive $NonInteractive

    # 4. Select the subscription the user chose.
    Initialize-AzureContext -SubscriptionId $params.SubscriptionId

    # 5. Verify the bootstrap-created resource group before any deployment.
    Test-PrecreatedLabResourceGroup `
        -Name $params.ResourceGroupName `
        -Location $params.Location

    # 6. Last confirmation before spending money.
    Show-ConfigurationSummary `
        -Params $params `
        -NonInteractive $NonInteractive `
        -Approve $Approve

    # 7. The subscription-scoped policy initiative must already exist.
    Test-PolicyInitiativeBootstrap

    # 8. Deploy the RG-scoped stack (the long step). Unpack the returned object.
    $infraResult = Deploy-Infrastructure -Params $params
    $rgDeployment = $infraResult.Deployment

    # 9. Deploy the subscription-scoped extras. We pass a small purpose-built
    #    hashtable (not the full $params) carrying just what this step needs,
    #    including the RG deployment name so the two deployments are correlated.
    Deploy-SubscriptionResources -Params @{
        Location       = $params.Location
        DeploymentName = $infraResult.DeploymentName
        EnableDefender = $params.EnableDefender
    } -RgDeployment $rgDeployment

    # 10. Wire up kubectl. Resolve the cluster name from outputs, or fall back to
    #    the conventional "<prefix>-aks" name.
    $clusterName = if ($rgDeployment.Outputs.clusterName) { $rgDeployment.Outputs.clusterName.Value } else { "$($params.NamePrefix)-aks" }
    Set-KubectlAccess -ResourceGroupName $params.ResourceGroupName -ClusterName $clusterName

    # 11. Apply the in-cluster manifests.
    Install-KubernetesManifests

    # 12. Print outputs + next steps.
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
