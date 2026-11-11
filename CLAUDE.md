# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An AI security lab: one Bedrock-backed banking agent ("Inno", 5 tools) deployed twice from the same Terraform module, a **vulnerable** and a **hardened** posture, then hit by a YAML attack catalog (26 attacks, OWASP LLM Top 10 / MITRE ATLAS) plus 7 legitimate requests. InnovaBank and all data are fictional; the vulnerable code paths (secret in the system prompt, broad IAM, no tool policy) are **intentional** — don't "fix" them outside the control system described below.

## Commands

`PYTHONPATH` must include `app:harness:supplychain` (the Makefile exports it; pytest sets it via `pyproject.toml`).

```bash
make install                 # pip install -r requirements-dev.txt (boto3, pyyaml, pytest, moto)
make test                    # unit tests, AWS mocked with moto, no account needed
python -m pytest tests/test_policy.py::test_own_account_read_is_allowed -q   # single test
make offline                 # run catalog vs both postures in process; rewrites docs/results/offline.md and the README offline block
make ablation                # hardened minus one control at a time -> docs/results/ablation.md
make gate                    # supply chain gate: model-lock provenance, pickle scan, CycloneDX ML-BOM
python tests/check_regression.py results/offline-hardened.json   # CI regression guard

# Targeted harness runs
python -m innovabank_harness run --target offline --mode hardened --only PI-01,EA-02 --out results/x.json
python -m innovabank_harness run --target offline --mode hardened --controls=-taint_lock --out results/x.json  # note the = form for removals
```

Live (real AWS, costs money): `make deploy-vulnerable`, `make deploy-hardened` (Terraform apply, writes `infra/envs/<mode>/outputs.json`, then seeds), `make ask MSG="..." [MODE=vulnerable] [CUSTOMER=C-1002]`, `make attack-live && make report-live` (rewrites `docs/results/live.md` and the README live block), `make destroy`.

CI (`.github/workflows/ci.yml`) runs: tests + offline bench + regression guard; supply chain gate + proof the scanner rejects a malicious pickle; `terraform validate` on `infra/envs/{vulnerable,hardened}` and `infra/account`.

## Architecture

### Postures are just control sets
`app/innovabank/config.py` defines `ALL_CONTROLS` (12 named controls). `vulnerable` = none, `hardened` = all. `IB_CONTROLS` / `--controls` / Terraform `controls_override` accept `all`, `none`, an explicit list, or deltas like `-taint_lock,+output_filter`. When `budget` is off, limits are loosened. **Every check runs in both postures**; `cfg.on(control)` only decides whether it is enforced. Disabled checks still emit a security event with action `observed` (enforced → `blocked`) — so new checks should follow the pattern `trace.event(...); if cfg.on(control): block`.

### Request flow (`agent.py`, one orchestrator for both postures)
1. `_screen_input`: size budget, `guards.scan` (normalisation, decoding, injection patterns), optional Bedrock Guardrail.
2. Model loop (`model.converse`, Bedrock Converse shape) up to `max_tool_calls + 2` rounds. The final answer goes through `models.strip_reasoning` (Nova emits `<thinking>` blocks) in both postures; this is reply parsing, not a control, and must not log events.
3. Each tool call goes through `policy.evaluate` (`policy.py`) — ownership binding to the session customer, payee allowlist, transfer limit, schema validation, budget, and the **taint lock**: once `search_knowledge_base`/`read_document` returns, `transfer_funds`/`send_secure_message` are denied for the rest of the turn. This is code outside the model and is the control the design leans on most. When `tool_policy` is on, `send_secure_message` is offered without `to_email` (`tools.tool_specs`) and `Agent._bind_recipient` fills in the address on file; with it off (vulnerable, ablation) the model picks the recipient, which EA-02 relies on.
4. Untrusted tool output is scanned, possibly withheld, and spotlighted (nonce-delimited, marked as data).
5. `_screen_output`: canary/PII/link/markup filters, then Guardrail.

### Pluggable backends (same orchestrator, offline vs AWS)
| Concern | Offline (tests, harness `offline` target) | AWS (Lambda, `handlers.py`) |
|---|---|---|
| Model | `ScriptedModel` (emits Nova-style `<thinking>` blocks in `LocalTarget`) — obeys any injection whose `if_context_contains` marker actually reached its context | `BedrockModel` (Nova Lite) |
| Store | `MemoryStore` | `AwsStore` (DynamoDB tables + S3) |
| Tools | `LocalDispatcher` | `LambdaDispatcher` → one Lambda + IAM role per tool (never retried) |
| Signing | `LocalSigner` | `KmsSigner` (ECDSA P-256, verify-only for ingest) |
| Embeddings | `LocalEmbedder` | `BedrockEmbedder` (Titan v2) |
| Guardrail | `NullGuardrail` (not exercised offline) | `BedrockGuardrail` |

Store/dispatcher implementations must keep identical interfaces. `ingest.py` indexes a KB doc only if signed (`ingest_integrity`) and clean (`ingest_scan`), else quarantines.

### Security events
`seclog.py` `EVENTS` maps each `ib_event` to an ATLAS technique and OWASP category; events are JSON lines on stdout. `infra/modules/stack/detections.tf` builds CloudWatch metric filters/alarms keyed on `ib_event` — adding an event type means updating both, plus `docs/controls.md`.

### Harness (`harness/innovabank_harness/`)
- Attack YAML (`harness/attacks/NN-*.yaml`): `id`, `session` (customer), `prompt`, `compromised_model` (ScriptedModel steps: `tool`/`args`/`repeat`/`say`, `if_context_contains`; `{system_prompt}`/`{tool_results}` expand in `say`), and `success` conditions. `harness/benign.yaml` uses `expect` instead.
- `detectors.py` holds the ground-truth condition kinds (`transfer_to`, `outbox_to`, `response_contains`, `tool_executed`, `executed_tool_calls_over`, ...). No LLM judging; add a new kind here if a YAML needs one.
- `targets.py`: `LocalTarget` (in process) and `AwsTarget` (drives a deployed stack from its Terraform outputs; needs publisher/assessor credentials incl. `kms:Sign`).
- `report.py` renders results and rewrites the README between `<!-- IB:OFFLINE-RESULTS:START/END -->` and `<!-- IB:LIVE-RESULTS:START/END -->` markers — regenerate rather than hand-editing those blocks.

### Regression contract
`tests/check_regression.py` fails CI if any hardened attack succeeds beyond `ACCEPTED_RESIDUAL = {"PI-06", "RP-04"}`, any benign request breaks, or any benign request raises a security event (legitimate traffic must be quiet, or CloudWatch alarms fire on real customers). Changing the residual set requires updating `docs/threat-model.md` and the README "What still gets through" section.

### Infra
`infra/modules/stack` is the single module; `infra/envs/{vulnerable,hardened}` only set `mode` (plus optional `alarm_email`, `controls_override`). The Lambda zip is built from `app/` into `infra/modules/stack/.build/`. Config reaches Lambdas through `IB_*` env vars read by `Config.from_env()`. `infra/account` optionally enables Bedrock invocation logging. Model IDs are pinned in `supplychain/model-lock.yaml`.
