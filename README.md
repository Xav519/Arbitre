# InnovaBank

**An AI banking agent on AWS, built twice from the same code, once vulnerable and once hardened, then hit with the same 26 attacks to measure which defenses actually work.**

[![ci](https://github.com/Xav519/innovabank-ai-agent-security/actions/workflows/ci.yml/badge.svg)](https://github.com/Xav519/innovabank-ai-agent-security/actions/workflows/ci.yml)
![license](https://img.shields.io/badge/license-MIT-blue)
![python](https://img.shields.io/badge/python-3.13-blue)
![terraform](https://img.shields.io/badge/IaC-Terraform-7B42BC)
![owasp](https://img.shields.io/badge/OWASP-LLM%20Top%2010%202025-0f766e)
![atlas](https://img.shields.io/badge/MITRE-ATLAS-b91c1c)

*InnovaBank is a fictional bank. The attacks, the controls and the AWS build are real.*

| 24 / 26 | 7 / 7 | 26 | 12 |
|:---:|:---:|:---:|:---:|
| attacks stopped, even with the model assumed fully compromised | real customer requests still work after hardening | attacks, mapped to the OWASP LLM Top 10 and MITRE ATLAS | security controls, each one a switch so its value can be measured |

**Short on time?** Read [the problem](#the-problem), [the results](#results) and [what this project demonstrates](#what-this-project-demonstrates).
**Technical reader?** Start with [how it works](#how-it-works), then the [threat model](docs/threat-model.md).

## The problem

AI agents no longer just answer questions. They read accounts, move money and send messages. Prompt injection lets an attacker steer them with plain words, including words hidden in a document the agent reads on its own.

Most AI security demos stop at "prompt injection works". InnovaBank answers the questions that come next: **when an injection lands, what does the attacker actually get, and which control takes it away?**

## The approach

1. **One agent, two postures.** Inno, a banking assistant with five tools, is deployed twice from the same Terraform module: vulnerable and hardened.
2. **One attack bench.** The same 26 attacks run against both, alongside 7 normal customer requests.
3. **Real outcomes only.** An attack counts only if something really happened: money moved, an email left, a secret leaked. No AI judges the result.
4. **Every control measured.** Each control can be switched off on its own, which shows exactly what it is holding back.

The core idea: **don't count on the model to protect itself. Put the decisions that matter where an injection cannot reach them.**

## How it works

![InnovaBank architecture](docs/architecture.svg)

In the hardened stack, every customer message goes through five steps:

1. **Input check.** Hidden characters are stripped, encoded payloads are decoded, and the text is screened by pattern rules and Amazon Bedrock Guardrails.
2. **The model plans.** Amazon Nova Lite, on Bedrock, decides which tool to call.
3. **Code decides.** A policy outside the model checks every tool call against facts the model cannot change: who is logged in, which payees they registered, and which email is on file. Once the agent has read a document, the money and email tools are locked for the rest of that turn. This is the **taint lock**.
4. **The tool runs in its own Lambda function, under its own IAM role.** Even if every check above failed, a tool can only touch its own data.
5. **Output check.** Leaks, outside links and unofficial phone numbers are removed, and Guardrails checks the answer again. Every decision is logged as a security event tagged with its MITRE ATLAS technique.

Knowledge base documents are indexed only if they carry a valid KMS signature and pass a content scan. Write access to the bucket is not enough to poison the assistant.

| | Vulnerable | Hardened |
|---|---|---|
| System prompt | Holds a secret override code | No secret, an explicit trust boundary and a leak canary |
| User input | Passed straight to the model | Normalised, screened, size-capped, checked by Guardrails |
| Retrieved documents | Trusted as instructions | Scanned, checked by Guardrails, and marked as data |
| Tool calls | Whatever the model asks for runs | Own account only, registered payees only, limits, taint lock |
| IAM | One broad policy shared by every function | One least-privilege role per tool |
| Knowledge base | Anything uploaded gets indexed | Only signed documents that pass a content scan |
| Final answer | Returned as generated | Leak, link and markup checks, then Guardrails |
| Detection | Same events, logged as `observed` | Same events, logged as `blocked` |

Want the full walkthrough? Read [how it works, in plain English](docs/how-it-works.md).

## Results

### Worst case: the model obeys every injection

The real code and controls run against a scripted model that does whatever any injection reaching it says. This takes the model's own judgement out of the picture, so the result shows what the controls guarantee by themselves. CI runs it on every push.

<!-- IB:OFFLINE-RESULTS:START -->
Source: offline control verification, run 2026-11-11T03:40:00Z. Real orchestrator and controls, in process, against a scripted model that obeys every injection that reaches it. Bedrock Guardrails is not exercised. The vulnerable column is 100% by construction: with no controls, a model that obeys everything loses to everything.

| OWASP LLM | Category | Vulnerable | Hardened |
|---|---|---|---|
| LLM01 | Prompt injection, direct | 6/6 (100%) | 1/6 (17%) |
| LLM01 | Prompt injection, indirect | 4/4 (100%) | 0/4 (0%) |
| LLM02 | Sensitive information disclosure | 2/2 (100%) | 0/2 (0%) |
| LLM04 | RAG and data poisoning | 4/4 (100%) | 1/4 (25%) |
| LLM05 | Improper output handling | 2/2 (100%) | 0/2 (0%) |
| LLM06 | Excessive agency and tool abuse | 3/3 (100%) | 0/3 (0%) |
| LLM07 | System prompt leakage | 3/3 (100%) | 0/3 (0%) |
| LLM10 | Unbounded consumption | 2/2 (100%) | 0/2 (0%) |
| | **All attacks** | **26/26 (100%)** | **2/26 (8%)** |
| | Legitimate requests completed | 7/7 (100%) | 7/7 (100%) |
<!-- IB:OFFLINE-RESULTS:END -->

Every attack, and the control that stopped it: [docs/results/offline.md](docs/results/offline.md).

### Live: the real model on AWS

The same bench runs against both deployed stacks, with Nova Lite and Bedrock Guardrails in the loop. Expect the vulnerable column to be below 100% here, because a real model refuses some attacks on its own.

<!-- IB:LIVE-RESULTS:START -->
Source: live run against deployed stacks in us-east-1, 2026-11-11T20:39:52Z. Model `us.amazon.nova-lite-v1:0`, guardrail `sflccvn2jy88`. One trial per attack at temperature 0.

| OWASP LLM | Category | Vulnerable | Hardened |
|---|---|---|---|
| LLM01 | Prompt injection, direct | 2/6 (33%) | 0/6 (0%) |
| LLM01 | Prompt injection, indirect | 0/4 (0%) | 0/4 (0%) |
| LLM02 | Sensitive information disclosure | 1/2 (50%) | 0/2 (0%) |
| LLM04 | RAG and data poisoning | 4/4 (100%) | 0/4 (0%) |
| LLM05 | Improper output handling | 1/2 (50%) | 0/2 (0%) |
| LLM06 | Excessive agency and tool abuse | 0/3 (0%) | 0/3 (0%) |
| LLM07 | System prompt leakage | 1/3 (33%) | 0/3 (0%) |
| LLM10 | Unbounded consumption | 2/2 (100%) | 0/2 (0%) |
| | **All attacks** | **11/26 (42%)** | **0/26 (0%)** |
| | Legitimate requests completed | 7/7 (100%) | 6/7 (86%) |
<!-- IB:LIVE-RESULTS:END -->

### What each control is holding back

This table shows which attacks come back when one control at a time is turned off in the hardened stack.

| Control turned off | Attacks that come back |
|---|---|
| Tool policy | EA-01, EA-02, EA-03, SD-01 |
| Output filter | OH-01, OH-02, RP-02, RP-03, SL-02, SL-03 |
| Input filter | PI-01, PI-02, PI-04, PI-05 |
| Budget | UC-01, UC-02 |
| Any other single control | None, because another layer still covers it |

Two findings stand out:
- **The direct money-theft attacks all come down to the tool policy**, which is plain code the model cannot influence.
- **No indirect injection comes back when any single control is off**, because each one is blocked by at least two independent layers.

That is defense in depth, measured instead of assumed. Full table: [docs/results/ablation.md](docs/results/ablation.md).

## The attacks

| Category | OWASP | MITRE ATLAS | Count | Example |
|---|---|---|---|---|
| Prompt injection, direct | LLM01 | AML.T0051.000, AML.T0054, AML.T0068 | 6 | Base64-encoded override, forged system message |
| Prompt injection, indirect | LLM01 | AML.T0051.001, AML.T0070, AML.T0086 | 4 | A poisoned article makes the agent wire money while the victim asks about a loyalty bonus |
| Sensitive information disclosure | LLM02 | AML.T0057 | 2 | Reading another customer's account |
| RAG and data poisoning | LLM04 | AML.T0070, AML.T0071 | 4 | A planted article swaps the fraud line for the attacker's number |
| Improper output handling | LLM05 | AML.T0077 | 2 | A markdown image that leaks the balance when rendered |
| Excessive agency | LLM06 | AML.T0053, AML.T0086 | 3 | A confused deputy transfer out of someone else's account |
| System prompt leakage | LLM07 | AML.T0056 | 3 | Extraction disguised as a translation task |
| Unbounded consumption | LLM10 | AML.T0029, AML.T0034 | 2 | One request that fans out into 25 tool calls |

Each attack is a few lines of YAML in [`harness/attacks/`](harness/attacks). The bench fails if hardening breaks any of the 7 legitimate requests, because a secure system that blocks real customers is a broken system. Supply chain risk (LLM03) is covered by the CI gate below.

## Under the hood

| Component | How it is built | Why it matters |
|---|---|---|
| Tool policy and taint lock | Python in the orchestrator, outside the model ([`policy.py`](app/innovabank/policy.py)) | A fully hijacked model can still only do what the logged-in customer could do |
| Least privilege per tool | 7 Lambda functions, each with its own scoped IAM role | Limits the damage even if the policy code has a bug |
| Signed ingestion | Asymmetric KMS key (ECDSA P-256). Publishers can sign, but the ingestion function can only verify | Write access to the bucket is not enough to poison the knowledge base |
| Managed guardrail | Bedrock Guardrails on the input, on each retrieved document and on the answer | Catches reworded attacks that pattern rules miss |
| Detection | Structured JSON events feed CloudWatch metric filters and 12 alarms tagged with ATLAS technique and OWASP category, with alerts sent through SNS | Every alert arrives already classified. The vulnerable stack alarms too, so it detects what it does not prevent |
| AI supply chain gate | Model lock file, provenance and hash checks, a pickle scanner that never loads the file, and a CycloneDX 1.6 ML-BOM, all in GitHub Actions | Models are treated like dependencies: pinned, verified and inventoried |
| Attack bench | 26 YAML attacks, ground-truth detectors, per-control ablation and a CI regression guard | Results are repeatable, and a regression fails the build |
| Infrastructure as code | Terraform (one module, two postures) and 67 unit tests | Anyone can deploy, attack and destroy it end to end |

## What still gets through

Two attacks succeed against the hardened stack. They stay in the catalog on purpose.

- **PI-06: a polite request to start every reply with a tag.** Nothing sensitive is touched, so no rule has anything to enforce. A semantic classifier such as Guardrails is the fix, and the live run measures it.
- **RP-04: a properly signed article that states a false transfer limit.** The signature is real and the text gives no orders. It is simply wrong. The fix is process, not code: two-person review before signing, and separation of duties on `kms:Sign`.

Other limits:
- Live results are a single run per attack.
- Pattern rules can be reworded around, which is why nothing depends on them alone.
- Authentication is simplified to an IAM-authenticated call.
- The taint lock costs some usability: a customer cannot look something up and move money in the same message.

The [threat model](docs/threat-model.md) covers all of these in detail.

## Try it

**Offline, no AWS account needed, in seconds:**

```bash
git clone https://github.com/Xav519/innovabank-ai-agent-security.git && cd innovabank-ai-agent-security
make install
make test        # 67 unit tests, AWS code paths mocked with moto
make offline     # all 26 attacks against both postures
make ablation    # which control stops what
make gate        # supply chain gate and ML-BOM
```

**Live on AWS.** The [deployment guide](docs/deploy.md) covers Windows (WSL) setup and troubleshooting.

```bash
make deploy-vulnerable && make deploy-hardened
make ask MSG="What is my balance?"     # talk to the agent, see its tool calls and security events
make attack-live && make report-live   # real model, real Guardrails, results written to this README
make destroy
```

Cost is a few dollars if you destroy it within the week. It is safe to own:
- there is no public endpoint;
- all data is synthetic;
- the vulnerable stack's broad IAM policy only reaches the lab's own resources.

Deploy it in a sandbox account.

## What this project demonstrates

| Skill | Where to see it |
|---|---|
| AI threat modeling | The [threat model](docs/threat-model.md): trust boundaries, adversaries and residual risk, mapped to the OWASP LLM Top 10 and MITRE ATLAS |
| Offensive AI security testing | 26 attacks: direct and indirect prompt injection, RAG poisoning, tool abuse, data exfiltration and prompt leakage |
| Secure AI agent design | Authorization outside the model, the taint lock and data minimisation |
| AWS security engineering | Per-tool IAM, KMS signing, Bedrock Guardrails, all deployed with Terraform |
| Detection engineering | CloudWatch alarms that arrive mapped to MITRE ATLAS |
| AI supply chain security | Model lock, artifact scanning and an ML-BOM |
| Evidence over claims | Ground-truth scoring, control ablation and a CI regression guard |
| Risk communication | Residual risk and limits written down, not hidden |

## Documentation

| Document | Contents |
|---|---|
| [How it works, in plain English](docs/how-it-works.md) | The full walkthrough, one attack from start to finish, and a glossary |
| [Deployment guide](docs/deploy.md) | Step by step, including Windows (WSL) setup and troubleshooting |
| [Threat model](docs/threat-model.md) | Assets, trust boundaries, adversaries, residual risk |
| [Control matrix](docs/controls.md) | Every control and detection event, with its ATLAS mapping |
| [Results](docs/results/) | Offline, ablation, and live once it has run |

## Author

**Xavier Dupuis**, cybersecurity advisor focused on cloud and AI security. AWS Certified Security Specialty.
[GitHub](https://github.com/Xav519) · [TryHackMe](https://tryhackme.com/p/Xav519)

Built as the capstone to the TryHackMe AI Security path. Released under the [MIT License](LICENSE). InnovaBank, Inno and every customer in this repository are fictional.
