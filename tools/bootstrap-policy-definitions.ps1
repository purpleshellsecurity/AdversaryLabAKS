<#
.SYNOPSIS
    Provisions the subscription-scoped Azure Policy definitions and initiative.

.DESCRIPTION
    Run this script as the bootstrap administrator before any OIDC or local lab
    deployment. It deploys infrastructure/modules/aks_policy_defs.bicep at the
    selected subscription scope. The GitHub Actions OIDC deployment identity
    does not invoke this script and has no subscription-scoped policy permissions.

.EXAMPLE
    Connect-AzAccount
    ./tools/bootstrap-policy-definitions.ps1 -SubscriptionId <subscription-id> -Location eastus2
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SubscriptionId,

    [Parameter(Mandatory)]
    [string]$Location
)

$ErrorActionPreference = 'Stop'

$templateFile = Join-Path $PSScriptRoot '..' 'infrastructure' 'modules' 'aks_policy_defs.bicep'
if (-not (Test-Path $templateFile)) {
    throw "Policy definition template not found: $templateFile"
}

Set-AzContext -SubscriptionId $SubscriptionId | Out-Null

New-AzSubscriptionDeployment `
    -Name "aks-lab-policy-definitions-$(Get-Date -Format 'yyyyMMddHHmmss')" `
    -Location $Location `
    -TemplateFile $templateFile `
    -ErrorAction Stop | Out-Null

Write-Host 'Azure Policy definitions and initiative are provisioned.' -ForegroundColor Green
