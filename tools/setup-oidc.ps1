# =============================================================================
# AKS Adversary Lab - OIDC Service Principal Setup
# =============================================================================
# Creates an App Registration with a Federated Credential for GitHub Actions
# OIDC authentication. No client secrets — token-based only.
#
# Usage:
#   ./setup-oidc.ps1 -GitHubOrg "yourorg" -GitHubRepo "aks-adversary-lab"
#
# Prerequisites:
#   - Az PowerShell module (Install-Module Az)
#   - Logged in: Connect-AzAccount
#   - Sufficient permissions: Application Administrator + Owner on subscription
# =============================================================================

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$GitHubOrg,

    [Parameter(Mandatory)]
    [string]$GitHubRepo,

    [Parameter()]
    [string]$AppName = "sp-aks-adversary-lab-github",

    [Parameter()]
    [string]$SubscriptionId = (Get-AzContext).Subscription.Id,

    [Parameter()]
    [string]$ResourceGroupName = "rg-aks-adversary-lab",

    [Parameter()]
    [ValidateSet("main", "master")]
    [string]$MainBranch = "main"
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

# ── Validate context ──────────────────────────────────────────────────────────

Write-Step "Validating Azure context"

$context = Get-AzContext
if (-not $context) {
    throw "Not logged in. Run Connect-AzAccount first."
}

$tenantId       = $context.Tenant.Id
$subscriptionId = $context.Subscription.Id

Write-Info "Tenant:       $tenantId"
Write-Info "Subscription: $subscriptionId"
Write-Info "Account:      $($context.Account.Id)"

# ── Create or get App Registration ───────────────────────────────────────────

Write-Step "Creating App Registration: $AppName"

$existingApp = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue

if ($existingApp) {
    Write-Info "App already exists — reusing: $($existingApp.AppId)"
    $app = $existingApp
} else {
    $app = New-AzADApplication -DisplayName $AppName
    Write-Success "Created App Registration: $($app.AppId)"
}

# ── Create or get Service Principal ──────────────────────────────────────────

Write-Step "Creating Service Principal"

$existingSp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue

if ($existingSp) {
    Write-Info "Service Principal already exists — reusing"
    $sp = $existingSp
} else {
    $sp = New-AzADServicePrincipal -ApplicationId $app.AppId
    Write-Success "Created Service Principal: $($sp.Id)"

    # Brief pause for AAD propagation
    Write-Info "Waiting 15s for AAD propagation..."
    Start-Sleep -Seconds 15
}

# ── Federated Credentials ─────────────────────────────────────────────────────
# Three credentials: main branch pushes, PRs, and manual workflow_dispatch

Write-Step "Configuring Federated Credentials (OIDC)"

$federatedCredentials = @(
    @{
        Name        = "github-push-main"
        Subject     = "repo:${GitHubOrg}/${GitHubRepo}:ref:refs/heads/${MainBranch}"
        Description = "GitHub Actions — push to $MainBranch"
    }
    @{
        Name        = "github-pull-request"
        Subject     = "repo:${GitHubOrg}/${GitHubRepo}:pull_request"
        Description = "GitHub Actions — pull requests"
    }
    @{
        Name        = "github-environment-lab"
        Subject     = "repo:${GitHubOrg}/${GitHubRepo}:environment:lab"
        Description = "GitHub Actions — lab environment (deploy/destroy)"
    }
)

foreach ($cred in $federatedCredentials) {
    $existing = Get-AzADAppFederatedCredential `
        -ApplicationObjectId $app.Id `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $cred.Name }

    if ($existing) {
        Write-Info "Federated credential already exists: $($cred.Name)"
    } else {
        New-AzADAppFederatedCredential `
            -ApplicationObjectId $app.Id `
            -Audience "api://AzureADTokenExchange" `
            -Issuer "https://token.actions.githubusercontent.com" `
            -Subject $cred.Subject `
            -Name $cred.Name `
            -Description $cred.Description | Out-Null

        Write-Success "Created: $($cred.Name)"
        Write-Info "  Subject: $($cred.Subject)"
    }
}

# ── Role Assignments ──────────────────────────────────────────────────────────

Write-Step "Assigning roles"

# Ensure resource group exists (create if not — idempotent)
$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    Write-Info "Resource group '$ResourceGroupName' not found — it will be created at deploy time"
    Write-Info "Assigning Contributor at subscription scope instead (needed to create the RG)"
    $rgScope = "/subscriptions/$subscriptionId"
} else {
    $rgScope = $rg.ResourceId
}

$roleAssignments = @(
    @{
        Role        = "Contributor"
        Scope       = $rgScope
        Description = "Deploy/manage lab resources in resource group"
    }
    @{
        Role        = "User Access Administrator"
        Scope       = "/subscriptions/$subscriptionId"
        Description = "Required for policy assignments and role assignments in Bicep"
    }
    @{
        Role        = "Resource Policy Contributor"
        Scope       = "/subscriptions/$subscriptionId"
        Description = "Required to deploy custom policy definitions and initiatives"
    }
)

foreach ($assignment in $roleAssignments) {
    $existing = Get-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionName $assignment.Role `
        -Scope $assignment.Scope `
        -ErrorAction SilentlyContinue

    if ($existing) {
        Write-Info "Role already assigned: $($assignment.Role) @ $($assignment.Scope)"
    } else {
        New-AzRoleAssignment `
            -ObjectId $sp.Id `
            -RoleDefinitionName $assignment.Role `
            -Scope $assignment.Scope | Out-Null

        Write-Success "$($assignment.Role)"
        Write-Info "  Scope: $($assignment.Scope)"
        Write-Info "  Reason: $($assignment.Description)"
    }
}

# ── Output GitHub Secrets ─────────────────────────────────────────────────────

Write-Step "GitHub Secrets — add these to your repo"
Write-Host ""
Write-Host "  Repository Settings → Secrets and variables → Actions → New repository secret" -ForegroundColor Yellow
Write-Host ""

$secrets = @(
    @{ Name = "AZURE_CLIENT_ID";       Value = $app.AppId }
    @{ Name = "AZURE_TENANT_ID";       Value = $tenantId }
    @{ Name = "AZURE_SUBSCRIPTION_ID"; Value = $subscriptionId }
)

foreach ($secret in $secrets) {
    Write-Host ("  {0,-30} {1}" -f $secret.Name, $secret.Value) -ForegroundColor White
}

Write-Host ""

# ── Optional: GitHub CLI auto-set ────────────────────────────────────────────

Write-Step "Attempting to set secrets via GitHub CLI (gh)"

$ghInstalled = Get-Command gh -ErrorAction SilentlyContinue

if ($ghInstalled) {
    Write-Info "gh CLI found — setting secrets automatically"

    foreach ($secret in $secrets) {
        gh secret set $secret.Name --body $secret.Value --repo "$GitHubOrg/$GitHubRepo"
        Write-Success "Set: $($secret.Name)"
    }

    Write-Host ""
    Write-Success "All secrets configured via gh CLI"
} else {
    Write-Host "  gh CLI not found — copy the values above into GitHub manually" -ForegroundColor Yellow
    Write-Host "  Install: https://cli.github.com" -ForegroundColor Gray
}

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  OIDC setup complete" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
Write-Host "  App Registration : $AppName"
Write-Host "  Client ID        : $($app.AppId)"
Write-Host "  Tenant ID        : $tenantId"
Write-Host "  Subscription     : $subscriptionId"
Write-Host ""
Write-Host "  Federated credentials cover:"
Write-Host "    · Push to $MainBranch"
Write-Host "    · Pull requests"
Write-Host "    · 'lab' GitHub environment (workflow_dispatch deploy/destroy)"
Write-Host ""
Write-Host "  Next step: push deploy.yaml and trigger a deploy run" -ForegroundColor Green
Write-Host ""
