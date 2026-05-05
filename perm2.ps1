$WORKSPACE_RG="adversary-lab-rg2"
$SUBSCRIPTION_ID="194065fa-04a5-4390-bf20-f648148de4af"
$SP_OBJECT_ID="ba0d4238-270e-4895-b51d-045993ce6049"

az role assignment list --assignee "$SP_OBJECT_ID" --scope "/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$WORKSPACE_RG" -o table