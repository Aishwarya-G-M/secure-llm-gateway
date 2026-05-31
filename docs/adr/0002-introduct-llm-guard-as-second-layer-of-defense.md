# ADR-005: Add LLM Guard as Second-Layer Prompt Injection Defense

**Status:** Accepted  
**Date:** 2026-06-01

## Context

The existing `RuleInspector` uses YAML-defined regex patterns to detect known prompt-injection attacks. This first layer is fast and deterministic, but it is strongest against literal or near-literal attack patterns. Red-team testing showed that paraphrased, obfuscated, and less literal prompt-injection attempts can bypass a rules-only approach, which is a known challenge in prompt-injection defense and one reason OWASP recommends layered safeguards rather than reliance on a single control.[1][2]

To improve detection coverage without replacing the fast rule layer, a second-pass semantic detector is needed. This layer should remain external to the main LLM application flow so that enforcement happens in code, not inside the model's own reasoning path.[1][3]

## Decision

A second-layer input inspection component named `LLMGuardInspector` will be added after `RuleInspector`. This component uses Protect AI's `llm-guard` library and its `PromptInjection` scanner to perform model-backed prompt-injection detection on prompts that are not already blocked or reviewed by the rule layer.[4]

The request inspection flow is:

1. Run `RuleInspector` first.
2. If the rule layer returns `BLOCK` or `REVIEW`, stop immediately and return that verdict.
3. Otherwise, run `LLMGuardInspector`.
4. If LLM Guard returns `BLOCK` or `REVIEW`, stop immediately and return that verdict.
5. Otherwise, allow the request to proceed to the main LLM.

This makes `RuleInspector` the fast-path gate and `LLMGuardInspector` the semantic fallback layer. The second layer is intentionally used as defense-in-depth rather than primary enforcement.[2][1]

## Implementation Notes

The `LLMGuardInspector` wraps the `PromptInjection` scanner and calls `scanner.scan(text)` to obtain the validation result and risk score. The scanner is initialized once in the class constructor to avoid repeated cold-start costs on each request.[4]

The initial implementation scope is **input inspection only**. Output inspection remains rule-based for now, although OWASP guidance supports adding output filtering and additional guardrails in later phases.[2][3]

The initial policy is conservative:

- `BLOCK` stops the request.
- `REVIEW` also stops the request.
- `ALLOW` permits the request to continue.

This conservative choice is consistent with OWASP's guidance to use layered filtering and human approval or stronger controls for suspicious or higher-risk cases, while recognizing that exact `REVIEW` semantics remain application-specific.[1][2]

## Alternatives Considered

### 1. Remain rule-based only

A rules-only approach is fast, explainable, and easy to maintain, but it is weak against paraphrased or novel prompt-injection attempts. This was rejected because the known coverage gap conflicts with the project's security goals.[2][1]

### 2. Build a custom classifier first

A custom classifier could eventually provide tighter control over precision, recall, and scoring behavior. It was deferred because it requires labeled data, evaluation infrastructure, and model lifecycle management before the project has enough evidence to justify that complexity.[2]

### 3. Use a general-purpose LLM judge as the second layer

A general-purpose LLM judge offers flexibility, but it adds latency, cost, and a larger attack surface. This option was not chosen for the first implementation because a specialized guard component is a better fit for a gateway-layer security check.[2][4]

## Consequences

### Benefits

- Better coverage against ambiguous, paraphrased, and semantically similar prompt-injection attempts.[2][4]
- Preserves the low-latency regex fast path for obvious matches.[2]
- Keeps enforcement outside the main LLM call path, which is safer than relying only on system prompts or model self-policing.[1][3]

### Costs and Trade-offs

- The LLM Guard scanner introduces cold-start latency when its underlying model is first loaded.[4]
- A second detection layer can increase false positives and may require threshold tuning over time.[2]
- Treating `REVIEW` as a stop decision is conservative and may block some borderline benign prompts.
- The system now depends on an additional third-party security library and its model behavior over time.[4]

## Follow-up Work

- Add and maintain gateway-level tests proving the orchestration order: rules first, then LLM Guard only if rules allow.
- Document Phase 5 as a two-layer input defense architecture.
- Evaluate detection coverage across known attacks, paraphrased attacks, and benign prompts.
- Consider adding a second-layer output inspection phase in the future, since OWASP recommends output filtering as part of a broader LLM security posture.[2][3]
- Revisit whether `REVIEW` should remain a hard stop after collecting real false-positive and false-negative feedback.