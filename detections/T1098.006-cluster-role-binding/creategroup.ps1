# ============================================================================
# Setup helper (run once, by hand): provision the Entra ID (Azure AD) group and
# gather the IDs the lab's CI workflow needs. This is NOT part of the attack or the
# detection — it's operator prep so the T1098.006 bundle has an admin group to bind
# to and a workspace to query. Fill in "<rg-name>"/"<workspace-name>" for your env.
# (The placeholders are QUOTED — bare <angle brackets> are a PowerShell parse error.)
#
# IMPORTANT — the group NAME below is just a suggestion; the OBJECT ID is what
# matters. If your tenant already has an admin group, use that one instead of
# creating a second. Two similarly-named groups is a real trap: deploying with
# the wrong one succeeds, and only fails ~20 minutes later when kubectl reports
# "User does not have access to the resource in Azure". The deploy workflow's
# preflight now prints the group's name and members so you can catch that early.
# ============================================================================

# Create the Entra ID group that will hold cluster admins for the lab.
az ad group create --display-name "AKS-AdversaryLab-Admins" --mail-nickname "aks-adversarylab-admins"

# Add yourself to it

# Look up your own Entra object ID (the signed-in user) and capture it in a var...
$MY_OBJECT_ID = $(az ad signed-in-user show --query id -o tsv)
# ...then add that object as a member of the group.
az ad group member add --group "AKS-AdversaryLab-Admins" --member-id "$MY_OBJECT_ID"

# Confirm who is actually in the group before you use it — this is the step that
# catches "right name, wrong group".
az ad group member list --group "AKS-AdversaryLab-Admins" --query "[].{name:displayName, upn:userPrincipalName}" -o table

# Print the GROUP's object ID — paste this into the GitHub Actions workflow so the
# cluster grants this group admin access.
az ad group show --group "AKS-AdversaryLab-Admins" --query id -o tsv


# Print the Log Analytics WORKSPACE resource ID — this is the workspace that holds
# the AKSAudit logs the detection queries (query.kql / test.kql) run against, and
# where rule.bicep deploys the Sentinel analytics rule.
# (PowerShell continues a line with a backtick, not a backslash.)
az monitor log-analytics workspace show `
  --resource-group "<rg-name>" `
  --workspace-name "<workspace-name>" `
  --query id -o tsv
