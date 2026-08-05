# Security

This project is a research-oriented secure LLM gateway. It is not a turnkey production security product.

## Scope

The gateway inspects prompts and model responses, applies security policies, and blocks or sanitises unsafe interactions to reduce risks such as prompt injection, unsafe output, and sensitive-information leakage.

## Limitations

- Controls are probabilistic and rule-based; they do not guarantee complete protection.
- New attack patterns may bypass existing inspection and policy rules.
- This project does not provide formal governance, compliance, or incident-response processes.

## Reporting security issues

If you discover a significant security issue, please open an issue describing the behaviour and any relevant test cases.