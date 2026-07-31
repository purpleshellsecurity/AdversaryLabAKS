# GitHub Actions Workflows — A Line-by-Line Walkthrough

This document explains the two GitHub Actions workflows in `.github/workflows/`
in depth, aimed at someone who wants to *understand* them rather than just run
them. It assumes only light familiarity with GitHub Actions.

- **`validate.yaml`** — runs automatically on every pull request and push to
  `main`. It never touches Azure. It only checks that the code in the repo is
  well-formed and safe. Think of it as the "did we break anything?" gate.
- **`deploy.yaml`** — runs only when you manually click "Run workflow". It
  actually builds (or tears down) the live AKS lab in your Azure subscription.

If you read nothing else, read the [Mental Model](#mental-model) and
[How the two workflows relate](#how-the-two-workflows-relate) sections.

---

## Table of contents

- [GitHub Actions vocabulary (30-second refresher)](#github-actions-vocabulary-30-second-refresher)
- [Mental model](#mental-model)
- [How the two workflows relate](#how-the-two-workflows-relate)
- [Authentication: how the workflows reach Azure without a password](#authentication-how-the-workflows-reach-azure-without-a-password)
- [`validate.yaml` — the CI gate](#validateyaml--the-ci-gate)
- [`deploy.yaml` — the deploy/destroy workflow](#deployyaml--the-deploydestroy-workflow)
- [Cross-cutting patterns worth internalizing](#cross-cutting-patterns-worth-internalizing)
- [Glossary of the external Actions used](#glossary-of-the-external-actions-used)

---

## GitHub Actions vocabulary (30-second refresher)

You'll see these words throughout. Here's what each one means in this repo:

| Term | Meaning |
|---|---|
| **Workflow** | One `.yaml` file under `.github/workflows/`. Has a `name`, a set of triggers (`on:`), and one or more jobs. |
| **Trigger (`on:`)** | The event that starts a workflow: a pull request, a push, or a manual button click (`workflow_dispatch`). |
| **Job** | A named unit of work that runs on its own fresh virtual machine (`runs-on: ubuntu-latest`). Jobs run **in parallel** by default unless you declare dependencies with `needs:`. |
| **Step** | One command or one pre-built Action inside a job. Steps within a job run **top to bottom, in order**, on the same VM. |
| **`uses:`** | Run a pre-built, reusable Action from the Marketplace (e.g. `actions/checkout@v4`). |
| **`run:`** | Run a shell script you wrote inline. |
| **Runner** | The ephemeral virtual machine a job executes on. It's destroyed when the job ends — nothing persists between jobs unless you explicitly pass it. |
| **Secret** | An encrypted value stored in GitHub (`${{ secrets.NAME }}`), never printed in logs. |
| **Environment** | A named GitHub "environment" (here: `lab`) that can gate a job behind approvals and scope which secrets it can read. |

---

## Mental model

```
                    ┌─────────────────────────────────────────────┐
   You push code    │            validate.yaml (automatic)         │
   or open a PR ───▶│  9 checks run in parallel — no Azure access  │
                    │  "Is the code correct and safe to merge?"    │
                    └─────────────────────────────────────────────┘

                    ┌─────────────────────────────────────────────┐
   You click        │            deploy.yaml (manual only)         │
   "Run workflow"──▶│  preflight → deploy  OR  preflight → destroy │
   and fill a form  │  "Actually build/tear down the live lab."    │
                    └─────────────────────────────────────────────┘
```

The key distinction: **`validate.yaml` reasons about files; `deploy.yaml` changes
your cloud.** That's why validate runs on every commit and needs no cloud
credentials, while deploy is manual, requires approval through the `lab`
environment, and holds write access to Azure.

---

## How the two workflows relate

They share no code, but they cover the same artifacts from two angles:

- `validate.yaml` **statically checks** the Bicep templates, Kubernetes
  manifests, Helm chart, detection rules, and Python tooling — *without
  applying them anywhere.*
- `deploy.yaml` **actually applies** those same Bicep templates and Kubernetes
  manifests to a real cluster.

So a good workflow is: open a PR → `validate.yaml` proves the manifests are
schema-valid and the Bicep compiles → merge → later, manually run `deploy.yaml`
to stand up the lab. Validation catches the class of errors ("this YAML is
malformed", "this Bicep won't compile", "there's a secret in the history")
*before* you spend 15–20 minutes and real Azure money on a deploy that would
have failed anyway.

---

## Authentication: how the workflows reach Azure without a password

This is the single most important concept for understanding `deploy.yaml`, and
it's worth understanding before you read the steps.

The deploy workflow logs into Azure using **OIDC federated credentials** — there
is **no client secret stored anywhere**. Here's the chain:

1. A one-time setup script, `tools/setup-oidc.ps1`, creates an Azure AD (Entra)
   **App Registration** and attaches a **federated credential** that says, in
   effect: *"trust tokens issued by GitHub Actions for the repo
   `yourorg/aks-adversary-lab` running in the `lab` environment."*
2. That script stores three **non-secret identifiers** as GitHub secrets:
   `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`. (They're stored
   as secrets for tidiness, but they're identifiers, not passwords.)
3. When `deploy.yaml` runs, this block at the top:
   ```yaml
   permissions:
     id-token: write
     contents: read
   ```
   grants the job the right to ask GitHub for a short-lived **OIDC token**.
4. The `azure/login@v2` step presents that token to Azure. Azure checks it
   against the federated credential from step 1, and if the repo + environment
   match, hands back a short-lived Azure access token. No password ever travels.

This is why `deploy.yaml` declares `environment: lab` on every job: the federated
credential is scoped to that environment, and the `lab` environment is also where
you can require a manual approval before anything runs. `validate.yaml` has
**none** of this — no `permissions: id-token`, no `azure/login` — because it
never needs to touch your subscription.

> **Takeaway:** `id-token: write` + `azure/login@v2` + `environment: lab` +
> the three `AZURE_*` secrets together are the passwordless door into Azure.
> Remove any one and the deploy can't authenticate.

---

## `validate.yaml` — the CI gate

### Triggers and top-level config

```yaml
on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
```

Runs on two events: any pull request **targeting** `main`, and any push
**landing on** `main`. In practice that means it runs while you're iterating on a
PR, and again once the PR merges.

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

**Concurrency control.** The `group` key is unique per workflow + branch
(`github.ref`). `cancel-in-progress: true` means: if you push twice quickly to
the same branch, the older still-running validation is **cancelled** and only the
newest run continues. This saves runner minutes — you only care about the latest
commit's result. (Contrast this with deploy's concurrency, which is the
opposite: never cancel.)

There is **no** `permissions:` block and **no cloud login** anywhere in this
file. That's deliberate and is the security property that makes it safe to run
this automatically on every PR, including PRs from forks.

### The jobs (and why they're grouped in "stages")

The file is organized into three comment-marked stages. Most jobs are in Stage 1
and run fully in parallel; Stages 2 and 3 each contain a single job that `needs:`
a Stage 1 job, so it waits for that dependency.

```
Stage 1 (all parallel, independent):
  bicep-validate ─┐
  powershell-lint │
  secret-scan     │
  k8s-validate ───┤
  helm-lint       │   ... all start at once ...
  detection-validate
  detection-logic-test
  python-sast
  exception-check

Stage 2 (waits for its dependency):
  iac-scan         needs: bicep-validate

Stage 3 (waits for its dependency):
  trivy-scan       needs: k8s-validate
```

Why the `needs:` chains? It's an efficiency choice, not a hard requirement.
There's no point running the heavier Checkov IaC scan if the Bicep doesn't even
compile, and no point running the container CVE scan if the Kubernetes manifests
that reference those images are themselves invalid. So each Stage-1 job acts as a
cheap pre-check gate for the heavier Stage-2/3 job that depends on it.

Now, job by job:

#### `bicep-validate`
Installs the Bicep CLI, then compiles `main.bicep`, `main_subscription.bicep`,
and every module under `infrastructure/modules/`. `az bicep build` is a compile:
it fails on syntax errors and surfaces linter warnings. If Bicep won't compile
here, the deploy would fail too — this catches it in seconds instead of minutes.

#### `powershell-lint`
Runs **PSScriptAnalyzer** (the standard PowerShell linter) recursively over the
repo, at Warning + Error severity. It fails the job if any issue is found. Note
the long `$excludeRules` list — these are rules intentionally silenced because
they don't fit this repo's style (e.g. `PSAvoidUsingWriteHost` is excluded
because the scripts deliberately use `Write-Host` for colored console output).
Each excluded rule is a deliberate "we know, and we're OK with it" decision.

#### `secret-scan`
Runs **TruffleHog** across the git history. Note `fetch-depth: 0` in the
checkout — that pulls the **entire** commit history, not just the latest commit,
so TruffleHog can scan every past commit for leaked credentials. The
`--only-verified` flag means it only fails on secrets it can **actively confirm
are live** (e.g. by test-authenticating), which dramatically cuts false
positives. A random-looking string won't fail the build; a real, working AWS key
will.

#### `k8s-validate`
Installs **kubeconform** and validates every `.yaml`/`.yml` under `kubernetes/`
against the Kubernetes 1.34 API schemas. `-strict` rejects unknown fields (catches
typos in field names); `-ignore-missing-schemas` tolerates Custom Resource types
kubeconform doesn't have a schema for (like Falco or Sentinel CRDs) rather than
failing on them. This proves your manifests would be accepted by the API server
before you ever apply them.

#### `helm-lint`
Validates the Falco Helm chart under `helm/falco/`. It adds the upstream Falco
chart repo, pulls the pinned dependency (`helm dependency update`), then does the
clever part:
```bash
helm template falco helm/falco | grep -q "adversary-lab-rules"
```
`helm template` renders the chart to plain Kubernetes YAML *without installing
it*, and the `grep` asserts that the lab's **custom Falco rules actually made it
into the rendered output**. This catches a subtle failure mode: if someone
mis-nests a value in `values.yaml`, Helm won't error — it'll just silently drop
the custom rules. This grep turns that silent drop into a loud CI failure.

#### `detection-validate`
Runs `tools/detection-validator/validate.py`, which **structurally** checks every
KQL and Falco detection rule: required fields present, MITRE ATT&CK technique IDs
mapped, files well-formed. This is a *structure* check — "is this rule authored
correctly?" — not a "does the query actually detect the attack?" check. That
second question is the next job's job.

#### `detection-logic-test`  ← the most interesting job in the file
This is a **Tier 1 logic test**: it proves each KQL detection query actually
*works*, entirely offline, with no AKS cluster and no Log Analytics.

```yaml
services:
  kusto:
    image: mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
    ports: [8080:8080]
    env: { ACCEPT_EULA: "Y" }
```

The `services:` block spins up a **real Kusto engine** (the same query engine Log
Analytics uses) as a container alongside the job. Then
`tools/detection-tester/kql_test.py` does something elegant: for each rule it
loads recorded event fixtures (`detections/kql/tests/<rule>/`), binds them to the
audit table name using a KQL `let ... datatable(...)`, and appends the
**unmodified** detection query followed by `| count`. Because the `let` shadows
the real table name, the shipped query runs verbatim against the fixture rows.

Each test asserts the query **fires on the malicious sample** and **stays silent
on the benign sample**. That's a true end-to-end logic test of the detection —
you're running the exact query you'd deploy, just against canned data instead of
a live cluster. `--wait-seconds 180` gives the Kusto container time to become
ready before the tests run.

#### `python-sast`
Runs **Bandit**, a Python static-analysis security scanner, over `tools/`. `-ll`
restricts it to medium-severity-and-above findings. The inline comment notes the
plan to switch to CodeQL when the repo goes public (CodeQL needs GitHub Advanced
Security, which is free on public repos but paid on private ones).

#### `exception-check`
Runs `tools/check-exceptions.py`, which reads `docs/security-exceptions.yaml` and
emits GitHub `::warning::` annotations for any time-boxed security exception past
its expiration date. **This job never fails the build** — the script always exits
0. It's a "warn, don't gate" nudge so accepted-risk exceptions don't quietly live
forever. Entries marked `expiration_date: none` are permanent accepted risks and
are skipped.

#### `iac-scan` (Stage 2)
Runs **Checkov** against the Bicep in `infrastructure/`. Crucially
`soft_fail: true` — it reports misconfigurations but **does not fail the build**.
This is a lab that intentionally contains some insecure-by-design infrastructure
(the whole point is to attack it), so hard-failing on every Checkov finding would
be counterproductive. It `needs: bicep-validate` so it only runs once the Bicep
is known to compile.

#### `trivy-scan` (Stage 3)
Runs **Trivy** against the `bkimminich/juice-shop:latest` container image,
reporting CRITICAL/HIGH CVEs. `exit-code: 0` makes it a **soft fail** — Juice Shop
is a deliberately vulnerable app (it's the "victim" in the lab), so flagging its
CVEs as build failures would be nonsensical. The comment tells you to flip this to
`exit-code: 1` if you start scanning your *own* images, where you'd want CVEs to
block. It `needs: k8s-validate`.

### The through-line of `validate.yaml`

Notice the recurring philosophy: **hard-fail on things that are wrong
(malformed YAML, uncompilable Bicep, live secrets, broken detection logic), but
soft-fail on things that are intentionally insecure (the vulnerable app, the
insecure-by-design infra).** This is a *security lab*, so "insecure" is often the
feature, not the bug — and the CI is tuned to know the difference.

---

## `deploy.yaml` — the deploy/destroy workflow

### Trigger: a manual form

```yaml
on:
  workflow_dispatch:
    inputs: ...
```

`workflow_dispatch` means this workflow **only ever runs when a human clicks
"Run workflow"** in the Actions tab. Nothing here is automatic. The `inputs:`
define the form fields that human fills in:

| Input | Purpose | Notes |
|---|---|---|
| `action` | `deploy` or `destroy` | A dropdown (`type: choice`). This single field decides which of the two big jobs runs. |
| `name_prefix` | Names all resources | e.g. `purpleshell` → resource group `rg-purpleshell-aks-lab`. Validated to 3–15 lowercase alphanumerics. |
| `location` | Azure region | Dropdown of allowed regions, default `eastus`. |
| `authorized_ip` | Your public IP in CIDR | This locks the AKS API server down to *your* IP. Validated to be a real public IP. |
| `admin_group_id` | Entra group for cluster-admin | The Azure AD group whose members get AKS admin. |
| `existing_workspace_id` | Reuse a Log Analytics workspace | Optional. Blank = create a new one. |

### Top-level config

```yaml
concurrency:
  group: deploy-lab
  cancel-in-progress: false
```

Fixed group name `deploy-lab` (not per-branch like validate), and
`cancel-in-progress: **false**`. This is the deliberate opposite of validate:
you **never** want to cancel a half-finished deploy or destroy — interrupting
`az` mid-flight could leave Azure resources in a broken, half-created state. So
concurrent runs **queue** and wait their turn instead of cancelling each other.

```yaml
permissions:
  id-token: write   # allowed to request an OIDC token → used to log into Azure
  contents: read    # allowed to read the repo (for checkout)
env:
  RESOURCE_GROUP: rg-${{ github.event.inputs.name_prefix }}-aks-lab
```

`id-token: write` is the OIDC permission covered in
[Authentication](#authentication-how-the-workflows-reach-azure-without-a-password).
`RESOURCE_GROUP` is a workflow-wide variable derived from your `name_prefix`, so
every job refers to the same RG name consistently.

### The three jobs and their control flow

```
                     ┌───────────────┐
   workflow_dispatch │   preflight   │  always runs first
        (deploy) ───▶│  (validation +│
                     │  Azure login) │
                     └───────┬───────┘
                             │ needs: preflight
                 ┌───────────┴───────────┐
      if action  │                       │  if action
      == deploy  ▼                       ▼  == destroy
            ┌─────────┐             ┌──────────┐
            │ deploy  │             │ destroy  │
            └─────────┘             └──────────┘
```

`preflight` always runs. Then **exactly one** of `deploy`/`destroy` runs,
selected by the `if:` condition on each (`github.event.inputs.action == '...'`).
Both `needs: preflight`, so if preflight fails, neither proceeds. All three
declare `environment: lab`, which is what enforces approval + scopes the OIDC
credential.

### Job 1: `preflight` — fail fast, before touching Azure

The entire point of this job is to catch bad input **before** spending 15+
minutes on a deploy. Its steps:

1. **Validate name prefix** — regex `^[a-z][a-z0-9]{2,14}$`. Must start with a
   letter, 3–15 lowercase alphanumerics. (Azure resource-name rules.)
2. **Validate IP range** — this is the most thorough step. It:
   - checks CIDR shape (`x.x.x.x/y`),
   - rejects any octet > 255,
   - and **rejects private/reserved ranges** (RFC 1918 `10./172.16-31./192.168.`,
     loopback `127.`, link-local `169.254.`, multicast `224–239.`, reserved `0.`).
   Why reject private IPs? Because `authorized_ip` becomes the AKS API server's
   allowlist. A private IP there would either lock *you* out or be meaningless —
   the allowlist needs your **public** IP. The error even tells you to run
   `curl ifconfig.me` to find it.
3. **Validate existing workspace ID format** — only runs `if` you supplied one
   (`existing_workspace_id != ''`). Regex-checks it's a proper Log Analytics
   resource ID. `shopt -s nocasematch` makes the match case-insensitive because
   Azure resource IDs vary in casing (`resourceGroups` vs `resourcegroups`).
4. **Azure login** — first real cloud contact, via OIDC (no secret).
5. **Verify Azure access** — `az account show` proves the login actually worked
   and prints which subscription you're in.
6. **Verify existing workspace exists** — again `if` you supplied one: confirms
   the workspace ID you passed actually resolves to a real resource you can see.

Steps 1–3 need no cloud at all (pure input validation); 4–6 do a cheap
round-trip to Azure to confirm credentials and referenced resources. Nothing is
created here.

### Job 2: `deploy` — build the lab, layer by layer

Runs only `if github.event.inputs.action == 'deploy'`. The ordering of these
steps matters a great deal — it mirrors real infrastructure dependencies.

1. **Checkout / Azure login** — fresh runner, so it re-checks-out and
   re-authenticates (nothing carries over from `preflight`).
2. **Install Bicep** and **Install kubectl + kubelogin** — the CLIs this job
   needs. `kubelogin` is what lets `kubectl` authenticate to an AAD-integrated
   AKS cluster.
3. **Workspace mode** — prints whether it's using your existing workspace or
   creating a new one. Purely informational.
4. **Create resource group** — `az group create`, tagged with who/when deployed.
5. **Deploy main stack (Bicep)** — `az deployment group create` against
   `infrastructure/main.bicep`. This is the big one: AKS cluster, ACR, Key Vault,
   Log Analytics, networking, policies. Note how it captures the deployment's
   **outputs** into `$GITHUB_OUTPUT` (`cluster_name`, `workspace_id`,
   `acr_server`, `keyvault_name`, etc.). Those `steps.bicep.outputs.*` values get
   reused by every later step. `id: bicep` is what makes them addressable.
6. **Deploy subscription-scope resources** — a *second*, separate Bicep deploy
   (`az deployment sub create`) at **subscription** scope rather than resource
   group scope. This handles things that live above the RG: Defender for Cloud
   plans, activity-log forwarding. It only enables activity-log forwarding when
   you're creating a *new* workspace (if you brought your own, it assumes you've
   already wired that up).
7. **Allowlist runner IP on AKS API server** — a subtle but important step. The
   Bicep locked the API server down to *your* `authorized_ip`. But the GitHub
   runner isn't you — it has its own IP and needs to run `kubectl` against the
   cluster. So this step discovers the runner's public IP (`curl api.ipify.org`),
   **appends** it to the existing allowlist, and saves it as
   `steps.runner_ip.outputs.ip`. Note it *appends* (`${CURRENT_RANGES},...`) so it
   doesn't clobber your IP.
8. **Get AKS credentials** — pulls kubeconfig and runs
   `kubelogin convert-kubeconfig -l azurecli` so `kubectl` can authenticate.
9. **Apply Kubernetes layers, in dependency order:**
   - `namespaces/` first (everything else lives inside them),
   - `rbac/` (permissions),
   - `network-policies/` (segmentation),
   - **Falco** via Helm (the runtime threat detector — same chart validated in
     `helm-lint`). Note `|| echo` so a Falco timeout warns but doesn't fail the
     whole deploy,
   - `monitoring/`,
   - `victim-apps/` (Juice Shop etc.),
   - `red-team/` (attacker tooling).
   This order is not arbitrary — namespaces must exist before things go in them,
   RBAC/network policy should exist before workloads, and detection (Falco)
   should be watching before the victim/attacker workloads come up.
10. **Deployment summary** — prints a nice box with cluster name, ACR, Key Vault,
    workspace, and the exact `az aks get-credentials` command to connect.
11. **Remove runner IP from AKS allowlist** — note `if: always()`. This is
    **cleanup that runs even if an earlier step failed**, as long as the runner IP
    was recorded. It **restores the allowlist to your original `authorized_ip`**,
    removing the runner's temporary access. So the runner's window into the API
    server is open only for the duration of the job. This is the counterpart to
    step 7 and a nice security-hygiene pattern: grant narrow access, always
    revoke it.

> **The runner-IP dance (steps 7 + 11) in one sentence:** temporarily let the CI
> runner through the AKS firewall so it can configure the cluster, then always
> shut that hole again — leaving only *your* IP allowed.

### Job 3: `destroy` — tear it down in the right order

Runs only `if github.event.inputs.action == 'destroy'`.

1. **Azure login** and **Confirm target** — logs in, prints what's about to be
   deleted (and notes that a *pre-existing* workspace will be preserved).
2. **Delete AKS cluster first (synchronous)** — read the big comment block here;
   it explains a real Azure gotcha. AKS auto-creates a **node resource group**
   with a `ReadOnly` lock (a "deny assignment") that blocks *anyone but AKS* from
   deleting resources inside it. If you just `az group delete` the parent RG,
   it fails with `DenyAssignmentAuthorizationFailed`. The fix: delete the
   **cluster** first (`az aks delete --yes`, synchronously), which makes AKS
   itself dismantle the node RG cleanly. Only then delete the parent RG. The step
   discovers the cluster by listing the RG rather than assuming its name, so it's
   robust to partial/renamed deploys.
3. **Delete resource group** — `az group delete --no-wait` (fire-and-forget;
   Azure removes the rest asynchronously). Guarded by `az group exists` so it's a
   no-op if the RG is already gone.
4. **Clean up orphaned policy assignments** — the subscription-scope policy
   assignment (`aks-lab-mitre-logging`) lives *above* the RG, so deleting the RG
   doesn't remove it. This step finds and deletes it explicitly. Without this,
   repeated deploy/destroy cycles would leave dangling policy assignments.
5. **Destroy summary** — prints what was deleted and, importantly, what
   **persists at subscription scope and is intentionally not removed** (Defender
   pricing tiers, custom policy definitions, and any pre-existing workspace).

> **Why destroy is more than one `az group delete`:** two things live outside the
> resource group (the node-RG lock and the subscription-scope policy) and a
> naive delete trips over both. The ordering and the explicit policy cleanup are
> what make destroy reliably idempotent.

---

## Cross-cutting patterns worth internalizing

These show up repeatedly and are the "why is it written this way" answers:

1. **Passing data between steps** — `echo "key=value" >> $GITHUB_OUTPUT` writes a
   step output; `${{ steps.<id>.outputs.key }}` reads it later. This is how the
   Bicep deploy hands the cluster name to every step after it. Requires the
   producing step to have an `id:`.

2. **`if:` conditions** — `if: github.event.inputs.action == 'deploy'` on a job
   selects which branch of work runs. `if: always()` on a step forces cleanup to
   run even after failures. `if: <input> != ''` skips steps that only make sense
   with optional input.

3. **`needs:`** — declares job dependencies. In validate it's a cost gate (don't
   run the expensive scan if the cheap check failed); in deploy it enforces that
   `preflight` gates everything.

4. **`concurrency` chosen per intent** — validate cancels stale runs (you only
   care about the latest commit); deploy queues them (never interrupt a
   half-done cloud operation). Same feature, opposite settings, for good reasons.

5. **Hard-fail vs soft-fail, on purpose** — correctness errors fail the build;
   intentionally-insecure lab components (Juice Shop CVEs, insecure-by-design
   Bicep) only warn. The workflows encode the knowledge of which is which.

6. **Grant-then-revoke access** — the runner-IP steps open a firewall hole only
   as long as needed and *always* close it (`if: always()`), even on failure.

7. **Ephemeral runners** — each job is a clean VM. That's why `deploy` and
   `destroy` re-run checkout and `azure/login` even though `preflight` already
   did: nothing carries over between jobs.

---

## Glossary of the external Actions used

| Action / tool | Where | What it does |
|---|---|---|
| `actions/checkout@v4` | both | Clones the repo onto the runner. `fetch-depth: 0` = full history. |
| `azure/login@v2` | deploy | OIDC login to Azure — no stored password. |
| `azure/setup-helm@v4` | validate, deploy | Installs the Helm CLI. |
| `actions/setup-python@v5` | validate | Installs a specific Python version. |
| `trufflesecurity/trufflehog` | validate | Scans git history for verified live secrets. |
| `bridgecrewio/checkov-action@v12` | validate | Static IaC misconfiguration scanner (soft fail). |
| `aquasecurity/trivy-action` | validate | Container image CVE scanner (soft fail here). |
| `kubeconform` | validate | Validates K8s manifests against API schemas. |
| `PSScriptAnalyzer` | validate | PowerShell linter. |
| `bandit` | validate | Python security static analysis. |
| `kustainer` (Kusto emulator) | validate | Real Kusto engine used to logic-test KQL offline. |
| `az bicep` | both | Compiles / deploys Bicep IaC. |
| `kubectl` + `kubelogin` | deploy | Applies manifests; `kubelogin` handles AAD auth to AKS. |

---

*See also: `README.md` (§ CI/CD Pipeline and § Getting Started), the inline
comments now added to both workflow files, `tools/detection-tester/kql_test.py`
(how the offline KQL logic test works), and `tools/setup-oidc.ps1` (the one-time
OIDC setup that makes passwordless Azure login possible).*
