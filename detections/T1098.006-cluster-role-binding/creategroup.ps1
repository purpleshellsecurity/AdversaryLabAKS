# Create the group
az ad group create--display-name "AKS-AdversaryLab-Admins" --mail-nickname "aks-adversarylab-admins"

# Add yourself to it
MY_OBJECT_ID=$(az ad signed-in-user show --query id -o tsv)
az ad group member add --group "AKS-AdversaryLab-Admins" --member-id "$MY_OBJECT_ID"

# Get the Object ID to paste into the workflow
az ad group show --group "AKS-AdversaryLab-Admins" --query id -o tsv