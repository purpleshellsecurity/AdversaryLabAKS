# AKS Adversary Lab
A comprehensive AKS-based cybersecurity lab environment designed for security professionals to practice container threat detection, incident response, adversary emulation, and Kubernetes security monitoring using Microsoft Sentinel and Azure security services.

Extension of [Adversary Lab](https://github.com/purpleshellsecurity/adversary_lab) for **Azure Kubernetes Service**

## Overview

The AKS Adversary Lab provides a complete container security monitoring environment that includes:

- **AKS Cluster** with Azure CNI Overlay + Cilium eBPF dataplane
- **Microsoft Sentinel** SIEM/SOAR with 7 container-focused solutions
- **Log Analytics Workspace** with all 11 AKS diagnostic categories
- **Container Insights** for pod/node inventory, container logs, and metrics
- **Microsoft Defender for Containers** eBPF sensor for runtime detection (optional)
- **Azure Policy Initiative** with 10 security policies (5 custom + 5 built-in)
- **Azure Container Registry** with diagnostic logging
- **Key Vault** with CSI integration and diagnostic logging
- **Falco** runtime security with custom syscall-based rules
- **Red Team Tools** — kdigger, CDK, Peirates, kubectl, nmap, curl/wget
- **Victim Applications** — DVWA, vulnerable API, intentional misconfigs

## Repository Structure

```
aks-adversary-lab/
│
├── infrastructure/                          # Deploy once, change rarely
│   ├── modules/                             # Bicep modules (layered architecture)
│   │   ├── log_analytics.bicep              # Log Analytics workspace (90-day retention)
│   │   ├── aks_networking.bicep             # VNet, 3 subnets, NSGs
│   │   ├── aks_cluster.bicep                # AKS with full security profile
│   │   ├── aks_diagnostics.bicep            # All 11 diagnostic categories
│   │   ├── container_insights.bicep         # DCR + DCRA for Container Insights
│   │   ├── aks_acr.bicep                    # Azure Container Registry + diagnostics
│   │   ├── aks_acr_role.bicep               # AcrPull role assignment
│   │   ├── aks_keyvault.bicep               # Key Vault with RBAC + diagnostics
│   │   ├── aks_sentinel.bicep               # Sentinel + 7 solutions
│   │   ├── aks_policy_defs.bicep            # Policy definitions + initiative (subscription)
│   │   └── aks_policy.bicep                 # Policy assignment + roles (RG scope)
│   ├── main.bicep                           # Resource Group deployment orchestration
│   ├── main_subscription.bicep              # Subscription-level resources
│   └── aks_adversary_lab_deploy.ps1         # Main deployment script
│
├── kubernetes/                              # Kubernetes manifests only
│   ├── namespaces/namespaces.yaml           # 4 namespaces with PSA labels
│   ├── monitoring/container-insights-config.yaml
│   ├── network-policies/                    # Cilium network policies per namespace
│   ├── rbac/rbac.yaml                       # Roles, bindings, intentional misconfigs
│   ├── red-team/red-team-tools.yaml         # kdigger, CDK, Peirates, kubectl, nmap, curler
│   └── victim-apps/victim-apps.yaml         # DVWA, vulnerable API, test secrets
│
├── helm/                                    # Helm values files
│   └── falco-values.yaml                    # Falco Helm values with custom rules
│
├── detections/                              # Actively developed detection content
│   ├── kql/                                 # KQL detection rules (standalone)
│   │   ├── container-escape.kql
│   │   ├── crypto-mining.kql
│   │   └── lateral-movement.kql
│   └── falco/                               # Falco rules (standalone, source of truth)
│       ├── token-theft.yaml
│       ├── container-escape.yaml
│       ├── crypto-mining.yaml
│       └── reverse-shell.yaml
│
├── attack-simulations/                      # Red team scripts mapped to MITRE
│   ├── token-theft.sh
│   └── lateral-movement.sh
│
├── docs/                                    # Documentation
│   ├── SECURITY.md                          # Scanning policy and SLAs
│   ├── security-exceptions.yaml             # Accepted risk register
│   └── KQL_Container_Reference.md           # Query reference for all log tables
│
└── .github/
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        └── validate.yaml                    # CI/CD pipeline
```

## Architecture

![AKS Adversary Lab Architecture](docs/diagram.png)

## Prerequisites

### Required Software

| Software | Windows | macOS |
|----------|---------|-------|
| PowerShell 7 | `winget install --id Microsoft.PowerShell` | `brew install --cask powershell` |
| Azure PowerShell | `Install-Module -Name Az -Force` | `Install-Module -Name Az -Force` |
| Azure CLI | `winget install -e --id Microsoft.AzureCLI` | `brew install azure-cli` |
| Bicep CLI | `winget install -e --id Microsoft.Bicep` | `az bicep install` |
| kubectl | `winget install -e --id Kubernetes.kubectl` | `brew install kubectl` |
| kubelogin | `az aks install-cli` | `brew install kubelogin` |
| Helm | `winget install -e --id Helm.Helm` | `brew install helm` |

### Azure Requirements

- Azure subscription with **Contributor** permissions
- Ability to create resources at both **Resource Group** and **Subscription** levels
- Entra ID security group for AKS cluster-admin access

## Quick Start

### 1. Clone the Repository

```powershell
git clone https://github.com/purpleshellsecurity/aks-adversary-lab.git
cd aks-adversary-lab
```

### 2. Deploy the Lab

```powershell
# Default (Defender disabled for cost savings)
./infrastructure/aks_adversary_lab_deploy.ps1

# With Defender for Containers enabled
./infrastructure/aks_adversary_lab_deploy.ps1 -EnableDefender $true
```

### 3. Post-Deploy Setup

```bash
# Configure kubectl
kubelogin convert-kubeconfig -l azurecli
kubectl get nodes

# Apply manifests
kubectl apply -f kubernetes/namespaces/namespaces.yaml
kubectl apply -f kubernetes/network-policies/victim-netpol.yaml
kubectl apply -f kubernetes/network-policies/attacker-netpol.yaml
kubectl apply -f kubernetes/network-policies/monitoring-netpol.yaml
kubectl apply -f kubernetes/rbac/rbac.yaml
kubectl apply -f kubernetes/victim-apps/victim-apps.yaml

# Install Falco
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n monitoring -f helm/falco-values.yaml

# Deploy red team tools
kubectl apply -f kubernetes/red-team/red-team-tools.yaml
```

### 4. Run Attack Simulations

```bash
# Token theft (T1528)
kubectl exec -it peirates -n attacker -- /bin/sh
# Then run: bash /path/to/attack-simulations/token-theft.sh

# Lateral movement (T1550.001)
kubectl exec -it kubectl -n attacker -- /bin/sh
```

### 5. Verify Detections

```kql
// AKS Audit logs
AKSAudit | where TimeGenerated > ago(1h) | summarize count() by bin(TimeGenerated, 5m)

// Container Insights
ContainerLogV2 | where TimeGenerated > ago(1h) | summarize count() by PodNamespace

// Defender alerts (if enabled)
SecurityAlert | where TimeGenerated > ago(24h) | where ProductName has "Defender" | take 10
```

## Detection Content

Detection rules live in `detections/` as standalone files — the source of truth for all detection logic.

| Folder | Format | Purpose |
|--------|--------|---------|
| `detections/kql/` | KQL | Microsoft Sentinel analytics rules |
| `detections/falco/` | YAML | Falco runtime security rules |

Falco rules in `detections/falco/` are assembled into `helm/falco-values.yaml` for deployment. The standalone files exist for version control, validation, and easier review in PRs.

## Log Tables

| Table | Source | Key Detections |
|-------|--------|---------------|
| AKSAudit | API server (all ops) | exec, pod creation, secret access, RBAC changes |
| AKSAuditAdmin | API server (mutations) | RBAC escalation, daemonset creation, deletions |
| AKSControlPlane | guard, scheduler | auth failures, admission denials |
| ContainerLogV2 | Container stdout/stderr | crypto mining, token access, reverse shells |
| KubeEvents | Pod lifecycle | crash loops, image pull failures, OOMKills |
| KubePodInventory | Pod metadata | namespace drift, unexpected images |
| InsightsMetrics | CPU/memory/network | mining detection via CPU anomalies |
| SecurityAlert | Defender | binary drift, web shells, escape attempts |
| AzureActivity | ARM operations | resource deletions, policy changes |

## Cost Management

| Resource | Monthly Cost |
|----------|-------------|
| AKS Standard tier (control plane) | ~$73 |
| 1× D2s_v3 system node | ~$70 |
| 1× D2s_v3 user node | ~$70 |
| Log Analytics (90-day, ~5GB/day) | ~$35 |
| ACR Standard | ~$5 |
| **Total (running 24/7)** | **~$253/month** |

```bash
# Stop cluster when not in use
az aks stop --resource-group <rg> --name <cluster>
az aks start --resource-group <rg> --name <cluster>
```

## Cleanup

```powershell
Remove-AzResourceGroup -Name "aks-adversary-lab-<suffix>" -Force

# Subscription-level policy cleanup
Remove-AzPolicySetDefinition -Name 'aks-adversary-lab-logging-initiative' -Force -ErrorAction SilentlyContinue
Remove-AzPolicyDefinition -Name 'aks-dine-all-diag-categories' -Force -ErrorAction SilentlyContinue
Remove-AzPolicyDefinition -Name 'aks-require-network-policy' -Force -ErrorAction SilentlyContinue
Remove-AzPolicyDefinition -Name 'aks-require-defender-sensor' -Force -ErrorAction SilentlyContinue
Remove-AzPolicyDefinition -Name 'aks-require-entra-rbac' -Force -ErrorAction SilentlyContinue
Remove-AzPolicyDefinition -Name 'kv-dine-diagnostic-settings' -Force -ErrorAction SilentlyContinue
```

## Contributing

See [docs/SECURITY.md](docs/SECURITY.md) for scanning policy and exception process.

Areas for enhancement:
- Additional KQL detection rules in `detections/kql/`
- Additional Falco rules in `detections/falco/`
- Attack simulation scripts in `attack-simulations/`
- Grafana dashboards

## Additional Resources

- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Sentinel Documentation](https://docs.microsoft.com/en-us/azure/sentinel/)
- [KQL Container Reference](docs/KQL_Container_Reference.md)
- [Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)

> [!NOTE]
> **Ready to start building detections?** Join [Adversary Lab Community](https://www.skool.com/adversary-lab-community/about)

## License

MIT License

> ⚠️ **Disclaimer:** This project deploys intentionally vulnerable workloads and offensive tools. Deploy only in isolated subscriptions you control.
