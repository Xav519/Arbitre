# InnovaBank. Run `make help` for the list of targets.

PY      ?= python3
REGION  ?= us-east-1
TF      ?= terraform
MODE    ?= hardened
CUSTOMER ?= C-1001
TRIALS  ?= 1
export PYTHONPATH := app:harness:supplychain

.DEFAULT_GOAL := help
.PHONY: help install test offline ablation gate gate-demo deploy-account deploy-vulnerable deploy-hardened \
        seed ask attack-live check-live report-live destroy clean

help: ## Show this help
	@grep -E '^[a-z -]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-20s %s\n", $$1, $$2}'

install: ## Install Python dependencies for tests, harness and gate
	$(PY) -m pip install -r requirements-dev.txt

test: ## Unit tests (no AWS account needed)
	$(PY) -m pytest -q

offline: ## Run the attack catalog in process against both postures and write the report
	$(PY) -m innovabank_harness run --target offline --mode vulnerable --out results/offline-vulnerable.json
	$(PY) -m innovabank_harness run --target offline --mode hardened --out results/offline-hardened.json
	$(PY) -m innovabank_harness report --vulnerable results/offline-vulnerable.json \
		--hardened results/offline-hardened.json --out docs/results/offline.md --readme README.md

ablation: ## Remove one control at a time and list the attacks that come back
	$(PY) -m innovabank_harness ablation

gate: ## Supply chain gate: provenance, artifact scan, ML-BOM
	$(PY) -m ib_supplychain gate

gate-demo: ## Show the scanner rejecting a malicious pickle (expected to fail)
	$(PY) supplychain/make_demo_fixture.py .demo-artifacts
	-$(PY) -m ib_supplychain scan .demo-artifacts
	rm -rf .demo-artifacts

deploy-account: ## Optional: enable Bedrock model invocation logging for the Region
	$(TF) -chdir=infra/account init -input=false
	$(TF) -chdir=infra/account apply -var region=$(REGION)

deploy-vulnerable deploy-hardened: deploy-%: ## Deploy one posture, then seed it
	$(TF) -chdir=infra/envs/$* init -input=false
	$(TF) -chdir=infra/envs/$* apply -var region=$(REGION)
	$(TF) -chdir=infra/envs/$* output -json > infra/envs/$*/outputs.json
	$(PY) -m innovabank_harness seed --outputs infra/envs/$*/outputs.json

seed: ## Re-seed both deployed stacks
	$(PY) -m innovabank_harness seed --outputs infra/envs/vulnerable/outputs.json
	$(PY) -m innovabank_harness seed --outputs infra/envs/hardened/outputs.json

ask: ## Talk to a deployed stack: make ask MSG="What is my balance?" [MODE=vulnerable] [CUSTOMER=C-1002]
	$(PY) -m innovabank_harness ask --outputs infra/envs/$(MODE)/outputs.json --customer $(CUSTOMER) "$(MSG)"

attack-live: ## Run the catalog against both deployed stacks (real Bedrock calls): make attack-live [TRIALS=3]
	$(PY) -m innovabank_harness run --target aws --outputs infra/envs/vulnerable/outputs.json --trials $(TRIALS) --out results/live-vulnerable.json
	$(PY) -m innovabank_harness run --target aws --outputs infra/envs/hardened/outputs.json --trials $(TRIALS) --out results/live-hardened.json

check-live: ## Regression guard on the last live hardened run
	$(PY) tests/check_regression.py results/live-hardened.json

report-live: ## Render the live report and update the README results block
	$(PY) -m innovabank_harness report --vulnerable results/live-vulnerable.json \
		--hardened results/live-hardened.json --out docs/results/live.md --readme README.md

destroy: ## Tear down both stacks
	-$(TF) -chdir=infra/envs/vulnerable destroy -var region=$(REGION)
	-$(TF) -chdir=infra/envs/hardened destroy -var region=$(REGION)

clean: ## Remove local build and cache files
	rm -rf .pytest_cache .demo-artifacts infra/modules/stack/.build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
