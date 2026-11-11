# Threat model

## System in one paragraph

Inno is a retail banking assistant. A customer sends a message, an orchestrator passes it to a foundation model on Amazon Bedrock together with five tools, and the model decides which tools to call. The tools read account data, move money, send messages and search or read a knowledge base stored in S3 and indexed in DynamoDB.

## Assets

| Asset | Why it matters |
|---|---|
| Customer funds | Direct financial loss |
| Customer records (balance, national id, email) | Privacy, regulatory exposure |
| Internal documents in the shared bucket | Credentials and operational detail |
| Integrity of the knowledge base | Customers act on what the assistant tells them |
| System prompt | Reveals logic, and in the vulnerable posture a working override code |
| Model and tool spend | Cost and availability |

## Trust boundaries

1. **Customer to orchestrator.** The message is untrusted. The identity is trusted, it comes from the authenticated session.
2. **Orchestrator to model.** The model is treated as untrusted. Its output is a request, not a decision.
3. **Knowledge base to model.** Retrieved text is untrusted, even when it was signed. A signature proves who published a document, not that it is true or harmless.
4. **Orchestrator to tools.** The only place where a model request becomes an action. This is where authorisation is enforced.
5. **Tools to data.** IAM fixes what each tool can touch regardless of what it is asked.
6. **Model source to runtime.** Models and weights are third-party components and are gated in CI.

## Adversaries

| ID | Who | Capability | Goal |
|---|---|---|---|
| A1 | Malicious customer | Authenticated, can send any message | Other customers' money and data, the system prompt, free compute |
| A2 | Content attacker | Write access to the knowledge base bucket, no signing rights | Reach other customers through the assistant |
| A3 | Compromised publisher | Can sign and publish documents | Same as A2, with a valid signature |
| A4 | Supply chain attacker | Controls or tampers with a model artifact | Code execution in the pipeline or at load time |

## Design assumption

**The model can be made to do anything an attacker wants.** Every control that matters is therefore placed where the model's output cannot reach: in the orchestrator's policy code, in IAM, and in the ingestion pipeline. Prompt wording and classifiers are used as well, but nothing depends on them alone.

The offline bench tests exactly this assumption. It replaces the model with a script that obeys any injection that reaches it and checks what the remaining controls still guarantee.

## Threats and controls

| Threat | Adversary | OWASP | ATLAS | Controls, in the order they act |
|---|---|---|---|---|
| Direct prompt injection | A1 | LLM01 | AML.T0051.000, AML.T0054, AML.T0068 | Input filter, Guardrails. If both miss: tool policy and output filter bound the impact |
| Indirect injection through a document | A2, A3 | LLM01 | AML.T0051.001 | Signed ingestion, ingestion scan, retrieval scan, Guardrails, spotlighting, taint lock, tool policy |
| Unauthorised transfer | A1, A2, A3 | LLM06 | AML.T0053 | Taint lock, tool policy (owner, payee, limit), per-tool IAM |
| Data exfiltration by message | A1, A2, A3 | LLM06 | AML.T0086 | Taint lock, recipient allowlist, data minimisation, output filter |
| Cross-customer data access | A1 | LLM02 | AML.T0057 | Tool policy ownership binding, data minimisation, output filter |
| Internal document access | A1 | LLM02 | AML.T0057 | Tool policy prefix check, IAM scoped to `kb/public/*`, credential pattern in output filter |
| Knowledge base poisoning, false contact or link | A2, A3 | LLM04 | AML.T0070, AML.T0071 | Signed ingestion (A2). Output filter contact and link allowlists (A3) |
| Knowledge base poisoning, false policy | A3 | LLM04 | AML.T0070 | None technical. See residual risk |
| Rendered-output exfiltration | A1, A2, A3 | LLM05 | AML.T0077 | Output filter strips markup, images and non-allowlisted links |
| System prompt extraction | A1 | LLM07 | AML.T0056 | Prompt hygiene (nothing secret to leak), input filter, canary in output filter, Guardrails |
| Resource exhaustion | A1 | LLM10 | AML.T0029, AML.T0034 | Input size cap, tool call budget |
| Malicious or swapped model artifact | A4 | LLM03 | AML.T0010, AML.T0011.000 | Model lock, provenance check, static artifact scan, ML-BOM |

## Residual risk

| Risk | Status |
|---|---|
| Harmless goal hijack (PI-06) | Accepted. No asset is exposed. A semantic classifier reduces it, measured in the live run |
| False information from a trusted publisher (RP-04) | Open. Needs process controls: two-person review, separation of duties on `kms:Sign`, alerting on publisher activity |
| Evasion of pattern-based filters | Expected. The filters reduce noise and cost. The tool policy and taint lock do not depend on them |
| Multi-turn attacks | Out of scope for this version. The bench is single turn. The taint lock would need to persist across turns |
| Model-level attacks (extraction, membership inference, training data poisoning) | Out of scope. InnovaBank uses managed foundation models and does not train |
| Compromise of the orchestrator itself | Out of scope. It is the trusted computing base, and standard workload hardening applies |

## Usability cost

Security controls are only credible if their cost is stated.

- The taint lock means a customer cannot look something up and move money in the same message.
- The contact and link allowlists must be maintained when official channels change.
- Signed ingestion adds a step for content authors, and a mis-signed document is silently absent from answers until someone checks the quarantine prefix. The `rag_document_rejected` alarm exists for that reason.
