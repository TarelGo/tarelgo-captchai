# Contributing to TarelGo CaptchAI

Thank you for considering a contribution! 🎯

## Ground rules

1. **English only** in code, comments, commit messages and documentation —
   this keeps the project accessible to the international community.
2. **No new heavy dependencies.** The project targets a plain multi-service
   VPS without Docker; the core dependency set is intentionally minimal.
3. **Security invariants are non-negotiable:**
   - every branch-B rejection stays a byte-identical `404` (no oracle);
   - HMAC comparisons only via `hmac.compare_digest`;
   - no PII, tokens or raw User-Agents in logs;
   - `fail-open` on branch A, `fail-closed` on branch B must be preserved.

## Development setup

```bash
git clone https://github.com/TarelGo/tarelgo-captchai.git
cd tarelgo-captchai
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[postgres,mariadb,dev]"
```

## Before you submit a PR

```bash
pytest           # all tests must pass (72 at the moment)
ruff check .     # zero lint findings
```

Guidelines:

- add or update tests for any behavior change (see `tests/` for style);
- keep lines ≤ 100 characters (`ruff` enforces it);
- configuration keys always use the `TARELGO_CAPTCHAI_` prefix and must be
  documented in `.env.example`;
- update `README.md` if you change endpoints, configuration or deployment.

## Commit messages

Use concise, imperative English, optionally with a scope tag:

```
detect: add JA4 fingerprint signal (optional, weight 3)
tokens: fix clock-skew edge case in expiry check
docs: describe the MariaDB topology
```

## Security issues

Please do not open public issues for vulnerabilities. Use
[GitHub Security Advisories](https://github.com/TarelGo/tarelgo-captchai/security/advisories/new)
so we can coordinate a fix before disclosure.

---

*TarelGo CaptchAI is part of the TarelGo ecosystem — https://tarelgo.com*
