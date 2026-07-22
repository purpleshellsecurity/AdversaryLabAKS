<#
.SYNOPSIS
    Deploys the AKS Adversary Lab - MITRE ATT&CK Containers environment.

.DESCRIPTION
    Automated deployment of a fully instrumented AKS cluster for adversary
    simulation and detection engineering, aligned to the MITRE ATT&CK
    Containers matrix. Deploys AKS with full diagnostic logging,
    Container Insights, Defender for Containers, Sentinel, ACR, and Key Vault.

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

[CmdletBinding()]
param(
    [string]$Location = "eastus2",
    [string]$AdminGroupObjectId,
    [string]$SubscriptionId,
    [string]$AuthorizedIpRange,
    [bool]$EnableDefender = $false
)

$ErrorActionPreference = "Stop"

# ── Helper Functions ────────────────────────────────────────────────────────

function Write-ColoredOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Get-PublicIPAddress {
    try {
        $ip = (Invoke-RestMethod -Uri "https://api.ipify.org" -TimeoutSec 10).Trim()
        if ($ip -match '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$') {
            return $ip
        }
        throw "Invalid IP format"
    }
    catch {
        Write-ColoredOutput "  Could not auto-detect IP." "Yellow"
        return $null
    }
}

function Test-Prerequisites {
    Write-ColoredOutput "[*] Checking prerequisites..." "Yellow"

    if (-not (Get-Module -ListAvailable -Name Az.Accounts)) {
        Write-ColoredOutput "[!] Azure PowerShell module not found. Install with:" "Red"
        Write-ColoredOutput "    Install-Module -Name Az -Repository PSGallery -Force" "White"
        exit 1
    }
    Write-ColoredOutput "  [+] Azure PowerShell module found." "Green"

    try {
        $bicepVersion = & bicep --version 2>&1
        Write-ColoredOutput "  [+] Bicep CLI: $bicepVersion" "Green"
    } catch {
        Write-ColoredOutput "[!] Bicep CLI not found. Install with:" "Red"
        Write-ColoredOutput "    winget install -e --id Microsoft.Bicep" "White"
        exit 1
    }

    try {
        $kubectlVersion = & kubectl version --client 2>&1 | Select-Object -First 1
        Write-ColoredOutput "  [+] kubectl: $kubectlVersion" "Green"
    } catch {
        Write-ColoredOutput "  [!] kubectl not found. Will be needed post-deployment." "Yellow"
    }

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
    param([string]$SubscriptionId)

    Write-ColoredOutput "`n[*] Authenticating to Azure..." "Yellow"

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        Connect-AzAccount
        $context = Get-AzContext
    }

    Write-ColoredOutput "  [+] Authenticated as: $($context.Account.Id)" "Green"
    Write-ColoredOutput "  [+] Tenant: $($context.Tenant.Id)" "Green"

    if ($SubscriptionId -and (Get-AzContext).Subscription.Id -ne $SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
    }
}

function Get-InteractiveParameters {
    param(
        [string]$Location,
        [string]$AdminGroupObjectId,
        [string]$SubscriptionId,
        [string]$AuthorizedIpRange,
        [bool]$EnableDefender
    )

    Write-ColoredOutput "`n[*] Collecting deployment parameters..." "Yellow"

    # Subscription
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
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

    # Generate unique lab suffix
    $labSuffix = -join ((97..122) + (48..57) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $ResourceGroupName = "aks-adversary-lab-$labSuffix"
    $NamePrefix = "lab$labSuffix"

    Write-ColoredOutput "  [+] Lab ID: $labSuffix" "Green"
    Write-ColoredOutput "  [+] Resource Group: $ResourceGroupName" "Green"
    Write-ColoredOutput "  [+] Resource Prefix: $NamePrefix" "Green"

    # Admin Group
    if (-not $AdminGroupObjectId) {
        Write-ColoredOutput "`n  [!] You need an Entra ID security group for AKS cluster-admin access." "Yellow"
        Write-ColoredOutput "      Create one in Entra ID > Groups, then provide the Object ID." "White"
        $AdminGroupObjectId = Read-Host "  Entra ID Admin Group Object ID"
    }

    # Authorized IP
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

    # Location
    $validLocations = @("eastus", "eastus2", "westus2", "westus3", "centralus", "northeurope", "westeurope", "uksouth", "southeastasia", "australiaeast")
    if (-not $Location -or $Location -eq "eastus2") {
        Write-ColoredOutput "`n  Select deployment region:" "Cyan"
        for ($i = 0; $i -lt $validLocations.Count; $i++) {
            $default = if ($validLocations[$i] -eq "eastus2") { " (default)" } else { "" }
            Write-ColoredOutput "    [$i] $($validLocations[$i])$default" "White"
        }
        $locSelection = Read-Host "  Select region (0-$($validLocations.Count - 1)) [1 for eastus2]"
        if ([string]::IsNullOrWhiteSpace($locSelection)) { $locSelection = 1 }
        $Location = $validLocations[[int]$locSelection]
    }
    Write-ColoredOutput "  [+] Region: $Location" "Green"

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

    $proceed = Read-Host "`nProceed with deployment? (Y/n)"
    if ($proceed -eq 'n' -or $proceed -eq 'N') {
        Write-ColoredOutput "Deployment cancelled." "Red"
        exit 0
    }
}

function New-LabResourceGroup {
    param([string]$Name, [string]$Location)

    Write-ColoredOutput "`n[*] Creating resource group: $Name..." "Yellow"
    New-AzResourceGroup -Name $Name -Location $Location -Force -Tag @{
        Environment = "SecurityLab"
        Project     = "AKS-Adversary-Lab"
        Purpose     = "MITRE-ATT&CK-Containers"
    } | Out-Null
    Write-ColoredOutput "  [+] Resource group created." "Green"
}

function Deploy-Infrastructure {
    param([hashtable]$Params)

    Write-ColoredOutput "`n[*] Deploying AKS Adversary Lab infrastructure (8-15 minutes)..." "Yellow"
    Write-ColoredOutput "    VNet, Log Analytics, ACR, Key Vault, AKS Cluster," "White"
    Write-ColoredOutput "    Diagnostics, Container Insights, Sentinel, Azure Policy" "White"

    $deploymentName = "aks-adversary-lab-$(Get-Date -Format 'yyyyMMdd-HHmmss')"

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

    if ($rgDeployment.ProvisioningState -ne 'Succeeded') {
        throw "Resource group deployment finished with state: $($rgDeployment.ProvisioningState)"
    }

    Write-ColoredOutput "  [+] Infrastructure deployment succeeded!" "Green"
    return @{ Deployment = $rgDeployment; DeploymentName = $deploymentName }
}

function Deploy-SubscriptionResources {
    param([hashtable]$Params, $RgDeployment)

    Write-ColoredOutput "`n[*] Deploying subscription-level resources (Defender, Activity logs)..." "Yellow"

    try {
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
        Write-ColoredOutput "  [!] Subscription deployment failed (non-critical): $_" "Yellow"
        Write-ColoredOutput "      You may need to enable Defender for Containers manually." "White"
    }
}

function Set-KubectlAccess {
    param([string]$ResourceGroupName, [string]$ClusterName)

    Write-ColoredOutput "`n[*] Configuring kubectl access..." "Yellow"

    if ([string]::IsNullOrEmpty($ClusterName)) {
        Write-ColoredOutput "  [!] Cluster name not available in outputs." "Yellow"
        return
    }

    if (Get-Command az -ErrorAction SilentlyContinue) {
        try {
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
    # Repo root is one level up from infrastructure/
    $repoRoot = Split-Path $PSScriptRoot -Parent

    if (-not (Get-Command kubectl -ErrorAction SilentlyContinue)) {
        Write-ColoredOutput "`n[!] kubectl not found. Apply manifests manually after installing kubectl." "Yellow"
        return
    }

    Write-ColoredOutput "`n[*] Applying Kubernetes manifests..." "Yellow"

    $manifests = @(
        @{ Path = "$repoRoot/kubernetes/monitoring/container-insights-config.yaml"; Desc = "Container Insights v2 schema (ContainerLogV2)" },
        @{ Path = "$repoRoot/kubernetes/namespaces/namespaces.yaml";               Desc = "Namespaces (attacker, victim, monitoring, security-tools)" },
        @{ Path = "$repoRoot/kubernetes/network-policies/victim-netpol.yaml";      Desc = "Victim namespace network policies" },
        @{ Path = "$repoRoot/kubernetes/network-policies/attacker-netpol.yaml";    Desc = "Attacker namespace network policies" },
        @{ Path = "$repoRoot/kubernetes/network-policies/monitoring-netpol.yaml";  Desc = "Monitoring namespace network policies" },
        @{ Path = "$repoRoot/kubernetes/rbac/rbac.yaml";                           Desc = "RBAC roles and bindings" },
        @{ Path = "$repoRoot/kubernetes/victim-apps/victim-apps.yaml";             Desc = "Victim applications (DVWA, vulnerable API)" }
    )

    foreach ($manifest in $manifests) {
        if (Test-Path $manifest.Path) {
            Write-ColoredOutput "  Applying: $($manifest.Desc)..." "White"
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
    param([hashtable]$Params, $RgDeployment)

    $repoRoot = Split-Path $PSScriptRoot -Parent

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

try {
    Write-ColoredOutput "`n=== AKS Adversary Lab ===" "Cyan"

    Test-Prerequisites

    $params = Get-InteractiveParameters `
        -Location $Location `
        -AdminGroupObjectId $AdminGroupObjectId `
        -SubscriptionId $SubscriptionId `
        -AuthorizedIpRange $AuthorizedIpRange `
        -EnableDefender $EnableDefender

    Initialize-AzureContext -SubscriptionId $params.SubscriptionId

    Show-ConfigurationSummary -Params $params

    New-LabResourceGroup -Name $params.ResourceGroupName -Location $params.Location

    $infraResult = Deploy-Infrastructure -Params $params
    $rgDeployment = $infraResult.Deployment

    Deploy-SubscriptionResources -Params @{
        Location       = $params.Location
        DeploymentName = $infraResult.DeploymentName
        EnableDefender = $params.EnableDefender
    } -RgDeployment $rgDeployment

    $clusterName = if ($rgDeployment.Outputs.clusterName) { $rgDeployment.Outputs.clusterName.Value } else { "$($params.NamePrefix)-aks" }
    Set-KubectlAccess -ResourceGroupName $params.ResourceGroupName -ClusterName $clusterName

    Install-KubernetesManifests

    Show-DeploymentSummary -Params $params -RgDeployment $rgDeployment

    Write-ColoredOutput "`nDeployment completed successfully!" "Green"
}
catch {
    Write-ColoredOutput "`n[!] Deployment failed: $($_.Exception.Message)" "Red"
    Write-ColoredOutput "    Check Azure Portal > Resource Group > Deployments for details." "Yellow"
    exit 1
}
finally {
    $params = $null
    $infraResult = $null
    $rgDeployment = $null
    [System.GC]::Collect()
}
