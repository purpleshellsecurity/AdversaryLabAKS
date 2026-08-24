# =============================================================================
# AKS Adversary Lab — local development entry point
# =============================================================================
# Every check CI runs, runnable locally in seconds. Before this existed, the
# only way to find out whether a detection validated was to commit, push, open
# a PR, and wait for twelve parallel jobs — and the knowledge of HOW to run each
# check lived only inside .github/workflows/validate.yaml.
#
# CI calls these same targets (with STRICT=1), so the two cannot drift: if a
# check passes locally and fails in CI, that is a bug in the Makefile rather
# than a surprise. STRICT=1 is the one difference — locally a missing tool skips
# with a warning, in CI it fails, because CI installs every tool.
#
#   make            list every target
#   make check      everything that needs no cluster and no cloud (start here)
#   make test       adds the Kusto emulator — needs Docker
#
# Targets are grouped: FAST (offline, seconds) → SLOW (containers) → LIVE
# (needs a deployed lab). Nothing in FAST touches Docker, Azure, or a cluster.
# =============================================================================

# Two interpreters, deliberately.
#
# PYTHON is whatever `python3` is, because that is where the repo's PyYAML
# actually lives on a typical machine — every tool except one runs fine on it.
#
# PYTHON_TEST prefers a 3.10+ interpreter because tools/detection-tester/kql_test.py
# uses `str | None` annotations, which raise TypeError at import time on Python
# 3.9 — still the macOS system python. Defaulting everything to 3.12 would fix
# that one tool and break the other four on a machine where 3.12 has no PyYAML.
PYTHON ?= $(shell command -v python3)
PYTHON_TEST ?= $(shell command -v python3.13 2>/dev/null || command -v python3.12 2>/dev/null || command -v python3)
KUSTO_IMAGE := mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
K8S_VERSION := 1.34.0

# STRICT=1 turns "tool missing, check skipped" into a hard failure. Local runs
# default to lenient so a contributor without every tool can still work; CI sets
# STRICT=1 because it installs them all, so a skip there means something broke.
STRICT ?= 0

.DEFAULT_GOAL := help

# ── Help ─────────────────────────────────────────────────────────────────────
# Self-documenting: every target with a `## comment` shows up here, so this file
# doubles as the CONTRIBUTING guide.

.PHONY: help
help:  ## Show this help
	@echo "AKS Adversary Lab — make targets"
	@echo ""
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "python:      $(PYTHON)"
	@echo "python-test: $(PYTHON_TEST)  (kql_test.py needs 3.10+)"

# ── FAST: offline checks, no Docker, no cloud, no cluster ───────────────────

# A missing optional tool SKIPS its check rather than failing the run — but the
# skip is reported loudly at the end. A silently-skipped check is worse than a
# failing one: it reads as "everything passed" when something was never looked
# at, which is precisely the failure mode this repo's CI exists to prevent.
.PHONY: check
check: validate wiring falco-parity arm-parity k8s  ## Run every offline check (start here)
	@echo ""
	@missing=""; \
	command -v kubeconform >/dev/null 2>&1 || missing="$$missing kubeconform(manifest-schemas)"; \
	$(PYTHON) tools/check-arm-parity.py >/dev/null 2>&1 || \
		{ [ $$? -eq 2 ] && missing="$$missing bicep-$$(cat infrastructure/.bicep-version)(arm-parity)"; }; \
	if [ -n "$$missing" ]; then \
		echo "Checks that RAN passed — but these were SKIPPED, not verified:"; \
		for m in $$missing; do echo "    - $$m"; done; \
		echo "  CI runs them regardless."; \
	else \
		echo "All offline checks passed."; \
	fi

.PHONY: validate
validate:  ## Structure-check every KQL + Falco rule
	$(PYTHON) tools/detection-validator/validate.py --detections-dir detections --verbose

.PHONY: wiring
wiring:  ## Assert every detection has metadata and is wired to a deployment
	$(PYTHON) tools/check-detection-wiring.py

.PHONY: falco-parity
falco-parity:  ## Assert helm/falco/values.yaml matches detections/falco/
	$(PYTHON) tools/build-falco-rules.py --check

.PHONY: falco-build
falco-build:  ## Regenerate helm/falco/values.yaml from detections/falco/
	$(PYTHON) tools/build-falco-rules.py

.PHONY: arm-parity
arm-parity:  ## Assert infrastructure/main.json matches main.bicep
	@$(PYTHON) tools/check-arm-parity.py; \
	rc=$$?; \
	if [ $$rc -eq 2 ] && [ "$(STRICT)" != "1" ]; then \
		echo "  (skipped — install Bicep $$(cat infrastructure/.bicep-version) to enable)"; \
		exit 0; \
	fi; \
	exit $$rc

.PHONY: arm-build
arm-build:  ## Regenerate infrastructure/main.json from main.bicep
	$(PYTHON) tools/check-arm-parity.py --write

.PHONY: k8s
k8s:  ## Schema-validate all Kubernetes manifests
	@# One shell block, not two: each recipe LINE gets its own shell, so an
	@# `exit 0` in a guard on its own line would not stop the next line running.
	@if command -v kubeconform >/dev/null 2>&1; then \
		kubeconform -strict -ignore-missing-schemas \
			-kubernetes-version $(K8S_VERSION) -summary kubernetes/; \
	elif [ "$(STRICT)" = "1" ]; then \
		echo "kubeconform missing and STRICT=1"; exit 1; \
	else \
		echo "  (skipped — brew install kubeconform to enable)"; \
	fi

.PHONY: bicep
bicep:  ## Compile all Bicep (syntax + linter warnings)
	az bicep build --file infrastructure/main.bicep --stdout > /dev/null
	az bicep build --file infrastructure/main_subscription.bicep --stdout > /dev/null
	@for f in infrastructure/modules/*.bicep; do \
		az bicep build --file "$$f" --stdout > /dev/null || exit 1; \
	done
	@echo "All Bicep compiles."

.PHONY: exceptions
exceptions:  ## Warn on expired entries in the security exception register
	$(PYTHON) tools/check-exceptions.py

.PHONY: test-dry
test-dry:  ## Compose the KQL test queries without running an engine
	$(PYTHON_TEST) tools/detection-tester/kql_test.py \
		--tests-dir detections/kql/tests --repo-root . --dry-run

# ── SLOW: needs Docker ──────────────────────────────────────────────────────

.PHONY: test
test:  ## Tier 1 KQL logic tests against a local Kusto emulator (needs Docker)
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
	@echo "Starting Kusto emulator..."
	@docker rm -f kustainer >/dev/null 2>&1 || true
	@docker run -d --rm --name kustainer -p 8080:8080 -e ACCEPT_EULA=Y $(KUSTO_IMAGE) >/dev/null
	@KUSTO_ENDPOINT=http://localhost:8080 KUSTO_DB=NetDefaultDB \
		$(PYTHON_TEST) tools/detection-tester/kql_test.py \
			--tests-dir detections/kql/tests --repo-root . --wait-seconds 180; \
		rc=$$?; docker rm -f kustainer >/dev/null 2>&1; exit $$rc

.PHONY: falco-validate
falco-validate:  ## Syntax-check Falco rules with Falco itself (needs Docker)
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
	@docker run --rm -v "$(PWD)/detections/falco:/rules:ro" \
		falcosecurity/falco-no-driver:latest \
		falco --validate /rules/_shared-lists.yaml $(patsubst detections/falco/%,--validate /rules/%,$(filter-out detections/falco/_shared-lists.yaml,$(wildcard detections/falco/*.yaml)))

# ── LIVE: needs a deployed lab and kubectl access ───────────────────────────

.PHONY: falco-noise
falco-noise:  ## Measure live Falco alert rates by rule (needs cluster access)
	@echo "Sampling Falco alerts for 60s across all nodes..."
	@for p in $$(kubectl get pods -n monitoring -l app.kubernetes.io/name=falco -o name); do \
		kubectl logs -n monitoring $$p -c falco --since=60s 2>/dev/null; \
	done | $(PYTHON) -c "import sys,json,collections; \
c=collections.Counter(); \
[c.update([json.loads(l).get('rule','?')]) for l in sys.stdin if l.strip().startswith('{')]; \
print('\n'.join(f'  {n:>6}/min  ~{n*1440:>8}/day  {r}' for r,n in c.most_common()))"

.PHONY: rules
rules:  ## List deployed Sentinel analytics rules (needs Azure access)
	@test -n "$(RG)" || { echo "usage: make rules RG=rg-<prefix>-aks-lab"; exit 1; }
	@ws=$$(az monitor log-analytics workspace list -g $(RG) --query "[0].name" -o tsv); \
	sub=$$(az account show --query id -o tsv); \
	az rest --method get --url "https://management.azure.com/subscriptions/$$sub/resourceGroups/$(RG)/providers/Microsoft.OperationalInsights/workspaces/$$ws/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-12-01-preview" \
		--query "value[?kind=='Scheduled'].{rule:properties.displayName, enabled:properties.enabled, severity:properties.severity}" -o table

# ── Housekeeping ────────────────────────────────────────────────────────────

.PHONY: clean
clean:  ## Remove build artifacts and caches
	@find . -name __pycache__ -type d -not -path "./.git/*" -exec rm -rf {} + 2>/dev/null || true
	@rm -f infrastructure/modules/*.json infrastructure/main_subscription.json
	@rm -rf helm/falco/charts
	@echo "Cleaned."

.PHONY: hooks
hooks:  ## Install the pre-commit hooks
	@# If `pip install pre-commit` fails with
	@#   "option use-deprecated: invalid choice: 'legacy-certs'"
	@# your pip config (~/.config/pip/pip.conf) carries an option modern pip
	@# rejects. PIP_CONFIG_FILE=/dev/null pip install pre-commit bypasses it.
	@command -v pre-commit >/dev/null 2>&1 || { \
		echo "pre-commit not installed — pip install pre-commit"; \
		echo "  (if pip errors on 'use-deprecated', prefix: PIP_CONFIG_FILE=/dev/null)"; \
		exit 1; }
	pre-commit install
	@echo "Hooks installed. Run 'pre-commit run --all-files' to check everything now."
