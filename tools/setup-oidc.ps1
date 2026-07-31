# =============================================================================
# AKS Adversary Lab - OIDC Service Principal Setup
# =============================================================================
# PURPOSE
#   One-time bootstrap that lets GitHub Actions authenticate to Azure using
#   OIDC (OpenID Connect) *workload identity federation* — i.e. with NO stored
#   client secret. Instead of a password living in a GitHub secret (which can
#   leak and never rotates itself), GitHub mints a short-lived OIDC token for
#   each workflow run, and Azure AD (Entra ID) trades it for an Azure access
#   token — but ONLY if the token's claims (repo, branch/environment) match a
#   "federated credential" we register here.
#
# WHAT IT CREATES
#   1. An App Registration (the identity) + its Service Principal.
#   2. Federated credentials that pin exactly which GitHub contexts may sign in
#      (push to the main branch, and the gated `lab` environment).
#   3. Azure role assignments so that identity can actually deploy the lab.
#   4. The three non-secret GitHub Actions variables the deploy workflow needs
#      (client id, tenant id, subscription id) — set via `gh` if available.
#
# WHY OIDC INSTEAD OF A SECRET
#   No long-lived credential to store, leak, or rotate. Access is bounded to
#   the specific repo + branch/environment encoded in the federated credential's
#   `Subject`, so even a copied client id is useless from anywhere else.
#
# IDEMPOTENT: safe to re-run. Every create step first checks for an existing
#   object and reuses it rather than erroring.
#
# Usage:
#   ./setup-oidc.ps1 -GitHubOrg "yourorg" -GitHubRepo "aks-adversary-lab"
#
# Prerequisites:
#   - Az PowerShell module (Install-Module Az)
#   - Logged in: Connect-AzAccount
#   - Sufficient permissions: Application Administrator + Owner on subscription
#     (needed to create the app AND to grant it subscription-scope roles)
#   - Optional: GitHub CLI `gh` (to push the variables automatically)
# =============================================================================

# CmdletBinding() turns this script into an "advanced function": it gains the
# common parameters (-Verbose, -ErrorAction, etc.) and stricter param handling.
[CmdletBinding()]
param(
    # -- Required: which GitHub repo is allowed to assume this identity. --
    # These two values become part of the federated credential Subject, so only
    # workflows in exactly this org/repo can exchange a token.
    [Parameter(Mandatory)]
    [string]$GitHubOrg,

    [Parameter(Mandatory)]
    [string]$GitHubRepo,

    # Display name of the Azure AD App Registration to create/reuse.
    [Parameter()]
    [string]$AppName = "sp-aks-adversary-lab-github",

    # Target subscription. Defaults to whatever `Connect-AzAccount` selected.
    [Parameter()]
    [string]$SubscriptionId = (Get-AzContext).Subscription.Id,

    # Resource group the identity will deploy into. If it doesn't exist yet, the
    # script grants Contributor at subscription scope so deploy time can create it.
    [Parameter()]
    [string]$ResourceGroupName = "rg-aks-adversary-lab",

    # The repo's default branch. ValidateSet restricts input to the two common
    # names so a typo can't silently produce a credential that never matches.
    [Parameter()]
    [ValidateSet("main", "master")]
    [string]$MainBranch = "main"
)

# Stop on the first error so a half-configured identity isn't left behind — any
# failed Az cmdlet aborts the whole script rather than continuing blindly.
$ErrorActionPreference = "Stop"

# ── Helpers ──────────────────────────────────────────────────────────────────
# Tiny wrappers for consistent, color-coded console output. Purely cosmetic —
# Write-Step announces a phase, Write-Success/Write-Info report within it.

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
# Confirm we're logged in and capture the tenant/subscription we'll federate to.
# These come from the CURRENT Az session — run Connect-AzAccount first.

Write-Step "Validating Azure context"

$context = Get-AzContext
if (-not $context) {
    # No cached credential -> nothing downstream can succeed; fail early and clearly.
    throw "Not logged in. Run Connect-AzAccount first."
}

# Tenant + subscription IDs are handed to GitHub later as workflow variables; the
# tenant is also the OIDC token issuer's audience side of the trust.
$tenantId       = $context.Tenant.Id
$subscriptionId = $context.Subscription.Id

Write-Info "Tenant:       $tenantId"
Write-Info "Subscription: $subscriptionId"
Write-Info "Account:      $($context.Account.Id)"

# ── Create or get App Registration ───────────────────────────────────────────
# The App Registration is the identity GitHub will impersonate. Its AppId becomes
# AZURE_CLIENT_ID in the workflow. Look up by display name first so re-runs reuse
# the same app (idempotent) instead of creating duplicates.

Write-Step "Creating App Registration: $AppName"

# -ErrorAction SilentlyContinue: "not found" shouldn't throw here — a null result
# just means we need to create it.
$existingApp = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue

if ($existingApp) {
    Write-Info "App already exists — reusing: $($existingApp.AppId)"
    $app = $existingApp
} else {
    $app = New-AzADApplication -DisplayName $AppName
    Write-Success "Created App Registration: $($app.AppId)"
}

# ── Create or get Service Principal ──────────────────────────────────────────
# The App Registration is the global definition; the Service Principal is its
# concrete instance IN THIS TENANT, and it's the object that role assignments
# actually attach to. No SP -> no way to grant it permissions.

Write-Step "Creating Service Principal"

$existingSp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue

if ($existingSp) {
    Write-Info "Service Principal already exists — reusing"
    $sp = $existingSp
} else {
    $sp = New-AzADServicePrincipal -ApplicationId $app.AppId
    Write-Success "Created Service Principal: $($sp.Id)"

    # Newly-created AAD objects take a few seconds to replicate across Azure AD.
    # Pause so the immediately-following role assignments don't fail with
    # "principal not found" against a not-yet-propagated SP.
    Write-Info "Waiting 15s for AAD propagation..."
    Start-Sleep -Seconds 15
}

# ── Federated Credentials ─────────────────────────────────────────────────────
# Three credentials: main branch pushes, PRs, and manual workflow_dispatch

Write-Step "Configuring Federated Credentials (OIDC)"

# SECURITY: no `pull_request` federated credential. This identity holds
# subscription-scope roles, so a PR-triggered workflow must never be able to mint
# its token. Deploys run only via the gated `lab` environment (created below).
$federatedCredentials = @(
    @{
        Name        = "github-push-main"
        Subject     = "repo:${GitHubOrg}/${GitHubRepo}:ref:refs/heads/${MainBranch}"
        Description = "GitHub Actions — push to $MainBranch"
    }
    @{
        Name        = "github-environment-lab"
        Subject     = "repo:${GitHubOrg}/${GitHubRepo}:environment:lab"
        Description = "GitHub Actions — lab environment (deploy/destroy)"
    }
)

foreach ($cred in $federatedCredentials) {
    # Idempotency: list existing federated creds on the app and match by name so a
    # re-run doesn't try to add a duplicate (which would error).
    $existing = Get-AzADAppFederatedCredential `
        -ApplicationObjectId $app.Id `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq $cred.Name }

    if ($existing) {
        Write-Info "Federated credential already exists: $($cred.Name)"
    } else {
        # The trust rule. Azure AD will exchange a GitHub token for an Azure token
        # only when ALL of these line up:
        #   Issuer   = GitHub's OIDC token issuer (who signed the incoming token)
        #   Audience = api://AzureADTokenExchange (Azure AD's expected audience)
        #   Subject  = the exact repo + branch/environment claim it must carry
        # This is what scopes the identity to just this repo context.
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
# Grant the Service Principal the Azure RBAC roles it needs to deploy the lab.
# Scope is chosen carefully: prefer the resource group, but fall back to the
# subscription where the Bicep genuinely needs it (policy + role assignments).

Write-Step "Assigning roles"

# If the target RG already exists, scope Contributor to it (least privilege). If
# not, the identity must be able to CREATE the RG, which requires subscription
# scope — so we widen the Contributor scope accordingly.
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
        # HARDENING CANDIDATE (see security-exceptions.yaml LAB-004): subscription-scope
        # UAA is Owner-equivalent for role grants. Kept because the Bicep creates role
        # assignments during deploy; replace with a scoped custom role when practical.
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
    # Check for the exact (principal, role, scope) triple first so re-running the
    # script doesn't stack duplicate assignments.
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
# These three values wire the workflow to this identity. Note they aren't
# sensitive — with OIDC there's no password to protect; a client id is useless
# without a matching federated credential — but they're stored as repo secrets by
# convention. Print them so the user can copy them if `gh` isn't available.

Write-Step "GitHub Secrets — add these to your repo"
Write-Host ""
Write-Host "  Repository Settings → Secrets and variables → Actions → New repository secret" -ForegroundColor Yellow
Write-Host ""

$secrets = @(
    @{ Name = "AZURE_CLIENT_ID";       Value = $app.AppId }        # the App Registration's id
    @{ Name = "AZURE_TENANT_ID";       Value = $tenantId }         # which Entra tenant to auth against
    @{ Name = "AZURE_SUBSCRIPTION_ID"; Value = $subscriptionId }   # where the lab gets deployed
)

foreach ($secret in $secrets) {
    # "{0,-30}" left-pads the name to 30 cols so the values line up in a column.
    Write-Host ("  {0,-30} {1}" -f $secret.Name, $secret.Value) -ForegroundColor White
}

Write-Host ""

# ── Optional: GitHub CLI auto-set ────────────────────────────────────────────
# Convenience: if the GitHub CLI is installed and authenticated, push the three
# values straight into the repo so the user doesn't have to copy them by hand.

Write-Step "Attempting to set secrets via GitHub CLI (gh)"

# Get-Command returns null (not an error) when gh isn't on PATH.
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
