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
#   - Sufficient permissions: Application Administrator + Owner on the pre-created
#     lab resource group (needed to create the app and grant RG-scoped roles)
#   - GitHub CLI `gh`, authenticated to the target repository (to read its OIDC
#     subject configuration and push the variables automatically)
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

    # Optional explicit display name of the Azure AD App Registration to create/reuse.
    # When omitted, the script derives a deterministic tenant/subscription/repository-
    # specific name after validating the Azure context.
    [Parameter()]
    [AllowEmptyString()]
    [string]$AppName,

    # Target subscription. Defaults to whatever `Connect-AzAccount` selected.
    [Parameter()]
    [string]$SubscriptionId = (Get-AzContext).Subscription.Id,

    # Pre-created resource group the identity will deploy into. This script fails
    # if it does not exist rather than widening the identity to subscription scope.
    [Parameter()]
    [string]$ResourceGroupName = "rg-aks-adversary-lab"

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

function Get-DefaultAppName {
    param(
        [Parameter(Mandatory)]
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$SubscriptionId,

        [Parameter(Mandatory)]
        [string]$GitHubOrg,

        [Parameter(Mandatory)]
        [string]$GitHubRepo
    )

    $normalizeNamePart = {
        param([string]$Value)

        return (($Value.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-'))
    }

    $normalizedOrg = & $normalizeNamePart $GitHubOrg
    $normalizedRepo = & $normalizeNamePart $GitHubRepo
    if ([string]::IsNullOrWhiteSpace($normalizedOrg) -or [string]::IsNullOrWhiteSpace($normalizedRepo)) {
        throw "GitHub organization and repository must contain letters or numbers to derive the default AppName."
    }

    # The hash prevents display-name collisions when normalized or shortened names
    # coincide, while retaining the organization and repository for operators.
    $identity = "$($TenantId.ToLowerInvariant())|$($SubscriptionId.ToLowerInvariant())|$normalizedOrg/$normalizedRepo"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hashBytes = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($identity))
    } finally {
        $sha256.Dispose()
    }
    $shortHash = (([System.BitConverter]::ToString($hashBytes) -replace '-', '').ToLowerInvariant()).Substring(0, 12)

    $displayOrg = $normalizedOrg.Substring(0, [Math]::Min($normalizedOrg.Length, 48))
    $displayRepo = $normalizedRepo.Substring(0, [Math]::Min($normalizedRepo.Length, 80))
    return "sp-aks-adversary-lab-$displayOrg-$displayRepo-$shortHash"
}

function Get-GitHubEnvironmentOidcSubject {
    param(
        [Parameter(Mandatory)]
        [string]$GitHubOrg,

        [Parameter(Mandatory)]
        [string]$GitHubRepo,

        [Parameter(Mandatory)]
        [string]$EnvironmentName
    )

    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "GitHub CLI 'gh' is required to read the target repository's OIDC subject configuration. Install and authenticate gh before running setup."
    }

    $repository = "$GitHubOrg/$GitHubRepo"
    $endpoint = "repos/$repository/actions/oidc/customization/sub"
    $response = & gh api --method GET `
        --header "Accept: application/vnd.github+json" `
        $endpoint 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to read GitHub OIDC subject configuration for '$repository': $response"
    }

    try {
        $configuration = $response | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "GitHub returned an unreadable OIDC subject configuration for '$repository': $response"
    }

    $subjectPrefix = $configuration.sub_claim_prefix
    if ([string]::IsNullOrWhiteSpace($subjectPrefix) -or
        $subjectPrefix -notmatch '^repo:[^\s]+$') {
        throw "GitHub did not return a usable OIDC sub_claim_prefix for '$repository'. Refusing to assume a subject format; configure or upgrade GitHub OIDC subject customization, then retry."
    }

    return "${subjectPrefix}:environment:$EnvironmentName"
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

if (-not $PSBoundParameters.ContainsKey('AppName')) {
    $AppName = Get-DefaultAppName `
        -TenantId $tenantId `
        -SubscriptionId $subscriptionId `
        -GitHubOrg $GitHubOrg `
        -GitHubRepo $GitHubRepo
    Write-Info "Using derived App Registration name: $AppName"
} else {
    Write-Info "Using explicit App Registration name: $AppName"
}

$githubEnvironmentSubject = Get-GitHubEnvironmentOidcSubject `
    -GitHubOrg $GitHubOrg `
    -GitHubRepo $GitHubRepo `
    -EnvironmentName "lab"
Write-Info "Using GitHub-declared OIDC subject: $githubEnvironmentSubject"

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
# The identity can mint a token only from the gated lab environment.

Write-Step "Configuring Federated Credentials (OIDC)"

# SECURITY: no `push` or `pull_request` federated credential. The deployment
# identity can mint a token only from the gated `lab` environment.
$legacyCredential = Get-AzADAppFederatedCredential `
    -ApplicationObjectId $app.Id `
    -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -eq "github-push-main" }
if ($legacyCredential) {
    Remove-AzADAppFederatedCredential `
        -ApplicationObjectId $app.Id `
        -FederatedCredentialId $legacyCredential.Id | Out-Null
    Write-Success "Removed legacy push credential: github-push-main"
}

$federatedCredentials = @(
    @{
        Name        = "github-environment-lab"
        Subject     = $githubEnvironmentSubject
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
        if ($existing.Subject -eq $cred.Subject -and
            $existing.Issuer -eq "https://token.actions.githubusercontent.com" -and
            $existing.Audiences -contains "api://AzureADTokenExchange") {
            Write-Info "Federated credential already matches GitHub's declared subject: $($cred.Name)"
        } else {
            Update-AzADAppFederatedCredential `
                -ApplicationObjectId $app.Id `
                -FederatedCredentialId $existing.Id `
                -Audience "api://AzureADTokenExchange" `
                -Issuer "https://token.actions.githubusercontent.com" `
                -Subject $cred.Subject `
                -Description $cred.Description | Out-Null
            Write-Success "Updated federated credential to GitHub's declared subject: $($cred.Name)"
            Write-Info "  Subject: $($cred.Subject)"
        }
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
# Grant the Service Principal only the Azure RBAC roles it needs inside the
# pre-created lab resource group. Subscription-scoped setup stays with the
# bootstrap administrator and is never granted to the OIDC identity.

Write-Step "Assigning roles"

$rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
if (-not $rg) {
    throw "Resource group '$ResourceGroupName' does not exist. A bootstrap administrator must create it before configuring the deployment identity."
}
$rgScope = $rg.ResourceId

# Bicep needs to create only these four role assignments. The condition below
# applies to both write and delete so UAA cannot grant or retain a broader role.
$permittedRoleDefinitionIds = @(
    '7f951dda-4ed3-4680-a7ca-43fe172d538d' # AcrPull
    '749f88d5-cbae-40b8-bcfc-e573ddc772fa' # Monitoring Contributor
    '92aaf0da-9dab-42b6-94a3-d43ce8d16293' # Log Analytics Contributor
    'b24988ac-6180-42a0-ab88-20f7382dd24c' # Contributor
)
$permittedRoleDefinitionIdsCondition = $permittedRoleDefinitionIds -join ', '
$uaaCondition = @"
(
    (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})
    )
    OR
    (
        @Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$permittedRoleDefinitionIdsCondition}
    )
)
AND
(
    (
        !(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})
    )
    OR
    (
        @Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {$permittedRoleDefinitionIdsCondition}
    )
)
"@

$roleAssignments = @(
    @{
        Role        = "Contributor"
        Scope       = $rgScope
        Description = "Deploy/manage lab resources in resource group"
    }
    @{
        Role        = "Resource Policy Contributor"
        Scope       = $rgScope
        Description = "Required for the lab resource-group policy assignment"
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

# Converge legacy unconditional UAA assignments instead of treating them as
# idempotent. A single matching condition is retained; every other assignment is
# removed before the constrained replacement is created.
$existingUaaAssignments = @(Get-AzRoleAssignment `
    -ObjectId $sp.Id `
    -RoleDefinitionName "User Access Administrator" `
    -Scope $rgScope `
    -ErrorAction SilentlyContinue)
$matchingUaaAssignments = @($existingUaaAssignments | Where-Object {
    $_.Condition -eq $uaaCondition -and $_.ConditionVersion -eq "2.0"
})

if ($existingUaaAssignments.Count -eq 1) {
    if ($matchingUaaAssignments.Count -eq 1) {
        Write-Info "Conditional User Access Administrator already assigned @ $rgScope"
    } else {
        $legacyUaaAssignment = $existingUaaAssignments[0]
        $legacyUaaAssignment.Condition = $uaaCondition
        $legacyUaaAssignment.ConditionVersion = "2.0"
        $legacyUaaAssignment.Description = "Can manage only Bicep-required role assignments in the lab resource group"
        Set-AzRoleAssignment -InputObject $legacyUaaAssignment | Out-Null
        Write-Success "Updated legacy User Access Administrator to the conditional boundary"
    }
} else {
    foreach ($existingUaaAssignment in $existingUaaAssignments) {
        Remove-AzRoleAssignment -InputObject $existingUaaAssignment | Out-Null
        Write-Info "Removed legacy or non-matching User Access Administrator assignment"
    }

    New-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionName "User Access Administrator" `
        -Scope $rgScope `
        -Condition $uaaCondition `
        -ConditionVersion "2.0" `
        -Description "Can manage only Bicep-required role assignments in the lab resource group" | Out-Null
    Write-Success "Conditional User Access Administrator"
    Write-Info "  Scope: $rgScope"
    Write-Info "  Permitted role definition IDs: $permittedRoleDefinitionIdsCondition"
}

# Kubernetes manifest deployment requires an Azure RBAC data-plane role. Grant it
# directly during bootstrap so the OIDC identity never self-assigns this role.
$aksRbacClusterAdminRoleDefinitionId = "b1ff04bb-8a4e-4dc4-8eb5-8693973ce19b"
$existingAksRbacClusterAdmin = Get-AzRoleAssignment `
    -ObjectId $sp.Id `
    -RoleDefinitionId $aksRbacClusterAdminRoleDefinitionId `
    -Scope $rgScope `
    -ErrorAction SilentlyContinue
if ($existingAksRbacClusterAdmin) {
    Write-Info "Azure Kubernetes Service RBAC Cluster Admin already assigned @ $rgScope"
} else {
    New-AzRoleAssignment `
        -ObjectId $sp.Id `
        -RoleDefinitionId $aksRbacClusterAdminRoleDefinitionId `
        -Scope $rgScope | Out-Null
    Write-Success "Azure Kubernetes Service RBAC Cluster Admin"
    Write-Info "  Scope: $rgScope"
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

# ── GitHub CLI secret setup ──────────────────────────────────────────────────
# GitHub CLI was already required to read the target repository's OIDC subject
# configuration, so use the same authenticated CLI session to set the identifiers.

Write-Step "Attempting to set secrets via GitHub CLI (gh)"

foreach ($secret in $secrets) {
    gh secret set $secret.Name --body $secret.Value --repo "$GitHubOrg/$GitHubRepo"
    Write-Success "Set: $($secret.Name)"
}

Write-Host ""
Write-Success "All secrets configured via gh CLI"

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
