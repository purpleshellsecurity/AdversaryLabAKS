# AKS Adversary Lab

A production-grade AKS security lab for container threat detection, adversary emulation, and detection engineering — aligned to the [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/).

Extension of [Adversary Lab](https://github.com/purpleshellsecurity/adversary_lab) for **Azure Kubernetes Service**.

> ⚠️ **Disclaimer:** This project deploys intentionally vulnerable workloads and offensive tooling. Deploy only in isolated Azure subscriptions you control.

---

## What Gets Deployed

| Component | Details |
|---|---|
| **AKS Cluster** | Azure CNI Overlay + Cilium eBPF dataplane, Entra ID RBAC, no local accounts |
| **Microsoft Sentinel** | 7 container-focused solutions, onboarded to Log Analytics |
| **Log Analytics Workspace** | All 11 AKS diagnostic categories, 90-day retention (or bring your own) |
| **Container Insights** | Pod/node inventory, container logs, metrics via DCR |
| **Defender for Containers** | eBPF sensor for runtime detection (optional) |
| **Azure Policy Initiative** | 10 policies (5 custom + 5 built-in) at subscription scope |
| **Azure Container Registry** | Standard SKU, AcrPull role for AKS kubelet identity |
| **Key Vault** | RBAC auth, purge protection, network deny-by-default |
| **Falco** | Runtime security via Helm, custom syscall-based rules |
| **Red Team Tools** | kdigger, CDK, Peirates, kubectl, nmap, curl — in `attacker` namespace |
| **Victim Apps** | Juice Shop, DVWA, vulnerable API, intentional misconfigs |

---

## Repository Structure

```
aks-adversary-lab/
├── .github/
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── workflows/
│       ├── validate.yaml          # Runs on every PR and push — never touches Azure
│       └── deploy.yaml            # Manual trigger — deploy or destroy the full stack
│
├── infrastructure/                # Bicep — deploy once, change rarely
│   ├── modules/                   # Layered architecture (Foundation → Compute → Monitoring → Governance)
│   │   ├── log_analytics.bicep
│   │   ├── aks_networking.bicep
│   │   ├── aks_cluster.bicep
│   │   ├── aks_diagnostics.bicep
│   │   ├── container_insights.bicep
│   │   ├── aks_acr.bicep
│   │   ├── aks_acr_role.bicep
│   │   ├── aks_keyvault.bicep
│   │   ├── aks_sentinel.bicep
│   │   ├── aks_policy_defs.bicep  # Subscription-scope policy definitions + initiative
│   │   └── aks_policy.bicep       # Policy assignment at resource group scope
│   ├── main.bicep                 # Resource group orchestrator
│   ├── main_subscription.bicep    # Subscription-scope resources (Defender pricing, activity logs)
│   └── aks_adversary_lab_deploy.ps1  # Local deploy script (alternative to GitHub Actions)
│
├── kubernetes/                    # K8s manifests — applied after cluster is up
│   ├── namespaces/
│   ├── monitoring/
│   ├── network-policies/
│   ├── rbac/
│   ├── red-team/
│   └── victim-apps/
│
├── helm/
│   └── falco/                     # Umbrella chart: pins Falco (Chart.yaml) + values.yaml
│
├── detections/                    # Source of truth for all detection content
│   ├── kql/                       # Microsoft Sentinel analytics rules
│   └── falco/                     # Falco runtime rules (assembled into helm/falco/values.yaml)
│
├── attack-simulations/            # Red team scripts mapped to MITRE ATT&CK
│   ├── token-theft.sh             # T1528
│   └── lateral-movement.sh        # T1550.001
│
├── tools/
│   ├── setup-oidc.ps1             # One-time OIDC setup for GitHub Actions
│   └── detection-validator/       # Python tool — validates KQL + Falco rule structure
│
└── docs/
    ├── SECURITY.md
    ├── security-exceptions.yaml   # Accepted risk register with justification + expiration
    └── KQL_Container_Reference.md
```

---

## CI/CD Pipeline

Every pull request and push to `main` runs `validate.yaml` automatically. The deploy workflow is always manual — nothing deploys to Azure without you clicking a button.

### Validation Pipeline (`validate.yaml`)

| Job | Tool | What it checks |
|---|---|---|
| `bicep-validate` | `az bicep build` | Syntax + linting on all Bicep files |
| `powershell-lint` | PSScriptAnalyzer | PowerShell script quality |
| `secret-scan` | TruffleHog | Verified secrets in commit history |
| `k8s-validate` | kubeconform | Kubernetes manifest schema validation |
| `helm-lint` | Helm | Falco values validity |
| `detection-validate` | validate.py | KQL + Falco rule structure |
| `python-sast` | Bandit | Python tooling security scan |
| `iac-scan` | Checkov | Bicep IaC security scan (soft fail) |
| `trivy-scan` | Trivy | Container CVE scan — Juice Shop image |

### Deploy Workflow (`deploy.yaml`)

Triggered manually via `workflow_dispatch`. Presents a form with inputs, runs preflight validation, then deploys or destroys the full stack in the correct order.

---

## Getting Started

### Prerequisites

| Tool | Install |
|---|---|
| PowerShell 7 | `winget install Microsoft.PowerShell` / `brew install --cask powershell` |
| Azure PowerShell | `Install-Module Az -Force` |
| Azure CLI | `winget install Microsoft.AzureCLI` / `brew install azure-cli` |
| kubectl | `az aks install-cli` |
| Helm | `winget install Helm.Helm` / `brew install helm` |
| gh CLI *(optional)* | `winget install GitHub.cli` / `brew install gh` — auto-sets GitHub secrets |

### Azure Requirements

- Azure subscription where you have **Owner** or **Contributor + User Access Administrator**
- Permission to create resources at **subscription scope** (policy definitions, Defender pricing)
- An **Entra ID security group** whose members will get `cluster-admin` on the AKS cluster

---

## Option A — GitHub Actions (Recommended)

This is the primary path. One-time setup, then spin up and down with a button click.

### Step 1 — OIDC Setup (run once)

From your local machine, logged into Azure:

```powershell
Connect-AzAccount

./tools/setup-oidc.ps1 `
  -GitHubOrg  "purpleshellsecurity" `
  -GitHubRepo "aks-adversary-lab"
```

The script:
- Creates an App Registration with a federated credential (no client secrets)
- Assigns the required roles at subscription and resource group scope
- Sets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID` as GitHub secrets — automatically if `gh` CLI is installed, otherwise prints values to copy manually

### Step 2 — Create GitHub Environment

1. Go to **Repo Settings → Environments → New environment**
2. Name it exactly **`lab`**
3. Optionally add yourself as a **required reviewer** — every deploy/destroy will pause for your approval before running

### Step 3 — Deploy

1. Go to **Actions → Deploy AKS Adversary Lab → Run workflow**
2. Fill in the form:

| Field | Description |
|---|---|
| `action` | `deploy` or `destroy` |
| `name_prefix` | Short lowercase prefix for resource names (e.g. `purpleshell`) |
| `location` | Azure region |
| `authorized_ip` | Your public IP in CIDR format — `curl ifconfig.me` then append `/32` |
| `admin_group_id` | Object ID of your Entra ID cluster-admin group |
| `existing_workspace_id` | *(Optional)* Resource ID of an existing Log Analytics workspace — leave blank to create a new one |

3. Click **Run workflow**

The workflow deploys in layers — Bicep first, then namespaces, RBAC, network policies, Falco, monitoring, victim apps, red team tools. Takes roughly 15–20 minutes end to end.

### Step 4 — Connect

```bash
az aks get-credentials \
  --resource-group rg-<name_prefix>-aks-lab \
  --name <name_prefix>-aks

kubelogin convert-kubeconfig -l azurecli
kubectl get nodes
```

### Step 5 — Tear Down

Same workflow, same inputs, change `action` to `destroy`. Deletes the resource group and cleans up orphaned subscription-scope policy assignments.

> **Note:** Defender for Cloud pricing tiers and custom policy definitions at subscription scope are **not** removed automatically. See the destroy job summary for manual cleanup commands.

---

## Option B — Local PowerShell Deploy

Use this when you want to deploy directly from your machine without the pipeline — useful for initial testing or when iterating on infrastructure changes.

```powershell
Connect-AzAccount

./infrastructure/aks_adversary_lab_deploy.ps1 `
  -Location          "eastus" `
  -AdminGroupObjectId "your-entra-group-object-id"

# With Defender for Containers enabled
./infrastructure/aks_adversary_lab_deploy.ps1 `
  -Location          "eastus" `
  -AdminGroupObjectId "your-entra-group-object-id" `
  -EnableDefender    $true
```

After the script completes, apply K8s resources manually:

```bash
kubectl apply -f kubernetes/namespaces/
kubectl apply -f kubernetes/rbac/
kubectl apply -f kubernetes/network-policies/
kubectl apply -f kubernetes/monitoring/
kubectl apply -f kubernetes/victim-apps/
kubectl apply -f kubernetes/red-team/

helm repo add falcosecurity https://falcosecurity.github.io/charts
helm dependency update helm/falco
helm upgrade --install falco helm/falco \
  --namespace monitoring \
  --create-namespace
```

> **Falco is a pinned chart dependency.** The version lives declaratively in
> `helm/falco/Chart.yaml` — a single source of truth, not scattered across deploy
> commands. Dependabot watches it and opens a PR when a new version ships; CI renders
> the chart and asserts the custom rules are present. To bump manually, edit `version:`
> in `helm/falco/Chart.yaml`, review the chart's `BREAKING-CHANGES.md`, and let CI validate.

---

## Running Attack Simulations

```bash
# Token theft — T1528
kubectl exec -it -n attacker \
  $(kubectl get pod -n attacker -l app=peirates -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/sh

# Inside the pod:
bash /attack-simulations/token-theft.sh

# Lateral movement — T1550.001
kubectl exec -it -n attacker \
  $(kubectl get pod -n attacker -l app=kubectl -o jsonpath='{.items[0].metadata.name}') \
  -- /bin/sh
```

---

## Verifying Detections

```kql
// AKS API server audit logs — confirm data is flowing
AKSAudit
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 5m)

// Container stdout/stderr
ContainerLogV2
| where TimeGenerated > ago(1h)
| summarize count() by PodNamespace

// Defender alerts (if enabled)
SecurityAlert
| where TimeGenerated > ago(24h)
| where ProductName has "Defender"
| project TimeGenerated, AlertName, Description, Entities
```

See [docs/KQL_Container_Reference.md](docs/KQL_Container_Reference.md) for the full query reference across all log tables.

---

## Log Tables Reference

| Table | Source | Key Detections |
|---|---|---|
| `AKSAudit` | API server (all ops) | exec, pod creation, secret access, RBAC changes |
| `AKSAuditAdmin` | API server (mutations) | RBAC escalation, daemonset creation, deletions |
| `AKSControlPlane` | guard, scheduler | auth failures, admission denials |
| `ContainerLogV2` | Container stdout/stderr | crypto mining, token access, reverse shells |
| `KubeEvents` | Pod lifecycle | crash loops, image pull failures, OOMKills |
| `KubePodInventory` | Pod metadata | namespace drift, unexpected images |
| `InsightsMetrics` | CPU/memory/network | mining detection via CPU anomalies |
| `SecurityAlert` | Defender | binary drift, web shells, escape attempts |
| `AzureActivity` | ARM operations | resource deletions, policy changes |

---

## Cost Estimate

Approximate monthly cost running 24/7:

| Resource | Cost |
|---|---|
| AKS Standard tier (control plane) | ~$73 |
| 1× D2s_v3 system node | ~$70 |
| 1× D2s_v3 user node | ~$70 |
| Log Analytics (~5 GB/day, 90-day retention) | ~$35 |
| ACR Standard | ~$5 |
| **Total** | **~$253/month** |

For engagements or training sessions, deploy for the session and destroy when done — cost is negligible at a few hours.

```bash
# Pause the cluster between sessions instead of destroying
az aks stop  --resource-group rg-<prefix>-aks-lab --name <prefix>-aks
az aks start --resource-group rg-<prefix>-aks-lab --name <prefix>-aks
```

---

## Detection Content

Detection rules in `detections/` are the source of truth — version controlled, validated in CI, reviewed in PRs like code.

| Location | Format | Purpose |
|---|---|---|
| `detections/kql/` | `.kql` | Microsoft Sentinel analytics rules |
| `detections/falco/` | `.yaml` | Falco runtime rules |

Falco rules are assembled from `detections/falco/` into `helm/falco/values.yaml` for deployment. The standalone files exist for validation, diffing, and easier review.

---

## Additional Resources

- [MITRE ATT&CK Containers Matrix](https://attack.mitre.org/matrices/enterprise/containers/)
- [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)
- [Defender for Containers](https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction)
- [Falco Documentation](https://falco.org/docs/)
- [KQL Container Reference](docs/KQL_Container_Reference.md)



---

## License

MIT License
