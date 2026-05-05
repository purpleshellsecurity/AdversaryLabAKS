$WORKSPACE_RG="adversary-lab-rg2"
$SUBSCRIPTION_ID="194065fa-04a5-4390-bf20-f648148de4af"

# Get the OIDC service principal's object ID
$SP_OBJECT_ID=$(az ad sp list --display-name "sp-aks-adversary-lab-github" --query "[0].id" -o tsv)

Write-Host "SP Object ID: $SP_OBJECT_ID"

# Grant Contributor on the workspace's RG
az role assignment create --assignee-object-id "$SP_OBJECT_ID"  --assignee-principal-type ServicePrincipal --role "Contributor" --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$WORKSPACE_RG"


$WORKSPACE_RG="adversary-lab-rg2"
$SUBSCRIPTION_ID="194065fa-04a5-4390-bf20-f648148de4af"
$SP_OBJECT_ID="ba0d4238-270e-4895-b51d-045993ce6049"

az role assignment list --assignee "$SP_OBJECT_ID" --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$WORKSPACE_RG" \-o table