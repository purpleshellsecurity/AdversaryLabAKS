## Summary
Brief description of what this PR does.

## Type of Change
- [ ] Infrastructure change (Bicep)
- [ ] Kubernetes manifest update
- [ ] Helm values update
- [ ] Detection rule (KQL/Falco/Sigma)
- [ ] Attack simulation script
- [ ] PowerShell script update
- [ ] Bug fix
- [ ] Documentation
- [ ] Security improvement

## Testing Done
- [ ] `az bicep build --file infrastructure/main.bicep` passes locally
- [ ] Kubernetes manifests validated with `kubectl apply --dry-run=client`
- [ ] Helm values validated with `helm lint`
- [ ] Detection rules tested against live data
- [ ] What-if deployment ran successfully
- [ ] Tested end-to-end in an isolated subscription

## Checklist
- [ ] Module placed in correct dependency layer (see infrastructure/modules/)
- [ ] No credentials, IPs, or kubeconfigs hardcoded
- [ ] Kubernetes RBAC follows least privilege
- [ ] Detection rules include MITRE ATT&CK technique mapping
- [ ] README updated if user-facing behavior changed

## MITRE ATT&CK Coverage (if applicable)
Techniques added or modified:
- T1XXX — description
