## Summary
Brief description of what this PR does.

## Type of Change
- [ ] New Bicep module
- [ ] Kubernetes manifest update
- [ ] Helm values update
- [ ] PowerShell script update
- [ ] Bug fix
- [ ] Documentation
- [ ] Security improvement

## Testing Done
- [ ] `az bicep build --file main.bicep` passes locally
- [ ] Kubernetes manifests validated with `kubectl apply --dry-run=client`
- [ ] Helm values validated with `helm lint`
- [ ] What-if deployment ran successfully
- [ ] Tested end-to-end in an isolated subscription

## Checklist
- [ ] Module placed in correct dependency layer (see CONTRIBUTING.md if applicable)
- [ ] No credentials, IPs, or kubeconfigs hardcoded
- [ ] Kubernetes RBAC follows least privilege
- [ ] Outputs added for anything other modules need
- [ ] README updated if user-facing behavior changed

## MITRE ATT&CK Coverage (if applicable)
Techniques added or modified:
- T1XXX — description