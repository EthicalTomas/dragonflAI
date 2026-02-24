# Safety & Ethics Policy

dragonflAI is designed exclusively for **authorised security testing** under bug bounty programs or explicit written permission.

## Guardrails

1. **Scope enforcement** — the `scope/validator.py` module checks every target against the program's declared scope before any tool is invoked. Out-of-scope hosts are silently skipped.
2. **No destructive actions** — the tool wrappers (`tools/`) use read-only / passive reconnaissance commands only. No exploitation.
3. **Rate limiting** — tool wrappers respect reasonable timeouts and avoid flooding targets.
4. **Artifact isolation** — recon output is stored locally in `artifacts/` (gitignored) and never transmitted to third parties.

## Responsible Use

- Only run dragonflAI against targets you are **explicitly authorised** to test.
- Comply with the platform's rules of engagement (HackerOne, Bugcrowd, etc.).
- Report findings responsibly through the appropriate disclosure channel.

## LLM Safety

The `llm/` module uses a `NullLLMProvider` stub by default. Any future LLM integration must:
- Avoid sending PII or credentials in prompts.
- Apply output validation before acting on model suggestions.
