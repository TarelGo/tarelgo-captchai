<div align="center">

# 🎯 TarelGo CaptchAI

### The cryptographic fork between AI agents and everyone else

One entry URL, two branches. A human who knows the URL, the algorithm
and even the headers still gets a byte-identical `404` on the AI branch.

[![CI](https://github.com/TarelGo/tarelgo-captchai/actions/workflows/ci.yml/badge.svg)](https://github.com/TarelGo/tarelgo-captchai/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-261230)](https://docs.astral.sh/ruff/)
[![Tests](https://img.shields.io/badge/tests-72%20passing-brightgreen)](#-testing--development)
[![RFC 9421](https://img.shields.io/badge/RFC-9421-informational)](https://www.rfc-editor.org/rfc/rfc9421)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-ff69b4)](CONTRIBUTING.md)

[🌐 Website](https://tarelgo.com) ·
[🎬 Live Demo](https://tarelgo.com/captcha-ai.html) ·
[📖 llms.txt](https://tarelgo.com/llms.txt) ·
[🐞 Report Bug](https://github.com/TarelGo/tarelgo-captchai/issues) ·
[💡 Request Feature](https://github.com/TarelGo/tarelgo-captchai/issues)

*Part of the TarelGo ecosystem — built by [TarelGo Development](https://tarelgo.com)*

</div>

---

## ✨ Why CaptchAI?

AI agents are increasingly indistinguishable from humans — and impersonating
a bot's `User-Agent` takes one line of code. Classical bot walls (CAPTCHA,
JS challenges, IP reputation) punish *everyone* and still leak to scripts.

**TarelGo CaptchAI flips the problem:**

- 🧑‍🤝‍🧑 **Humans and search engines never notice it.** The default branch A
  is your normal site — fail-open, always available, no challenges, no JS.
- 🤖 **AI agents get a dedicated machine-first branch** — clean Markdown,
  no banners, no trackers — *only* if they prove who they are
  cryptographically or via a fresh one-shot capability token.
- 🔐 **Knowing is not enough.** Branch B has no 401/403 oracle: every
  rejection is the same `404` as any unknown route, so the endpoint does
  not even advertise that it exists.

## 🎬 Live demo

> Demo endpoints are being rolled out on our infrastructure — the links
> below currently point to [tarelgo.com](https://tarelgo.com) placeholders.

| What you see | Link | Who can open it |
|---|---|---|
| 🌐 Branch A — the human site | [https://tarelgo.com](https://tarelgo.com) | everyone |
| 🤖 Branch B — AI-only content | [https://tarelgo.com/b](https://tarelgo.com/b) | verified AI agents only |
| 📄 Agent policy & auth guide | [https://tarelgo.com/llms.txt](https://tarelgo.com/llms.txt) | everyone (plain text) |
| ❤️ Health endpoint | [https://tarelgo.com/healthz](https://tarelgo.com/healthz) | everyone |

## 🧭 How it works

```
                 ┌──────────────────────────── GET / (the fork) ───────┐
  any request -> │  Web Bot Auth signature present and valid?          │
                 │     yes -> branch B content (Markdown for the LLM)  │
                 │     no  -> branch A page (humans, fail-open)        │
                 └─────────────────────────────────────────────────────┘
  POST /ai-token   best_effort only: scoring >= 3 and >= 2 categories
                   -> one-shot capability token (TTL 120 s, IP+UA bound)
  GET  /b          strict: RFC 9421 only. best_effort: token or signature.
                   any failure -> identical 404.
```

### Two protection modes

| Mode | Branch B opens with | Who needs it |
|---|---|---|
| `strict` *(default)* | [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) Web Bot Auth signature only | maximum guarantee, zero impostors |
| `best_effort` | signature **or** one-shot HMAC token from `POST /ai-token` | lets self-declared agents in after scoring |

The mode is switched by one environment variable — no code changes.

### Scoring (best_effort token gate)

| Category | Weight | Signals (browser-claim gated) |
|---|---|---|
| `ua` | 2 | User-Agent declares a known AI agent (GPTBot, ClaudeBot, …) |
| `fingerprint` | 2 | browser-claimed UA without `Sec-Fetch-*` / client hints |
| `tls` | 3 | JA3 hash from a TLS terminator matches the known-bot list |
| `behavior` | 1 | browser-claimed UA without `Accept-Language` etc. |

Decision B = score ≥ `threshold` (default **3**) **and** ≥ **2** independent
categories. The *browser-claim gating* is the trick: fingerprint and behavior
signals fire only when the client *pretends* to be a browser. That is what
makes the mismatch detectable — and it keeps plain `curl` (which never sends
`Sec-Fetch-*`) and real Chrome (which always does) both safely on branch A.

### Web Bot Auth (strict mode)

Full implementation of RFC 9421 HTTP Message Signatures with Ed25519 and the
`web-bot-auth` profile:

- `tag="web-bot-auth"`, `keyid` = RFC 7638 JWK thumbprint;
- `created` / `expires` freshness with configurable clock skew;
- `Signature-Agent` required and covered by the signature;
- `Content-Digest` verified whenever a body is present;
- agent public keys fetched from
  `https://<agent>/.well-known/http-message-signatures-directory` (JWKS),
  cached in the DB for 1 h with a negative cache;
- SSRF guard: https only, 2 s timeout, 64 KiB cap, private IPs blocked.

A signed request to `GET /` returns branch B content **directly** — a
redirect would destroy the signature, which covers `@path` of the original
target.

## 📑 Table of contents

- [Why CaptchAI?](#-why-captchai)
- [Live demo](#-live-demo)
- [How it works](#-how-it-works)
- [Quick start (2 minutes)](#-quick-start-2-minutes)
- [Production installation (Ubuntu 24.04)](#-production-installation-ubuntu-2404)
- [Proxy topologies](#-proxy-topologies)
- [Configuration](#%EF%B8%8F-configuration)
- [API reference](#-api-reference)
- [For AI agents](#-for-ai-agents)
- [Testing & development](#-testing--development)
- [Project structure](#-project-structure)
- [Security design](#%EF%B8%8F-security-design)
- [Performance](#-performance)
- [Roadmap](#%EF%B8%8F-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Links](#-links)

## 🚀 Quick start (2 minutes)

Requirements: **Python 3.11+** and `git`. No Docker, no Redis, no build tools.

```bash
git clone https://github.com/TarelGo/tarelgo-captchai.git
cd tarelgo-captchai

python3 -m venv .venv
source .venv/bin/activate
pip install -e .

# Run with in-memory storage (dev only) on 127.0.0.1:8008
export TARELGO_CAPTCHAI_ALLOW_MEMORY=true
export TARELGO_CAPTCHAI_MODE=best_effort
export TARELGO_CAPTCHAI_SECRETS=dev-only-secret-0123456789abcdef0123456789abcdef
python -m tarelgo_captchai
```

In a second terminal — act as an agent and take branch B:

```bash
# 1. Mint a one-shot capability token (score: fingerprint 2 + behavior 1 = 3)
curl -s -X POST http://127.0.0.1:8008/ai-token \
  -H 'User-Agent: Mozilla/5.0 (compatible; MyAIAgent/1.0; +https://myagent.example)'
# -> {"token":"tg1.0...","token_type":"capability","expires_in":120,...}

# 2. Open the AI-only branch with it (keep the SAME User-Agent — tokens are UA-bound)
curl -s http://127.0.0.1:8008/b \
  -H 'User-Agent: Mozilla/5.0 (compatible; MyAIAgent/1.0; +https://myagent.example)' \
  -H 'Authorization: Bearer <token from step 1>'
```

You are now reading branch B in Markdown. Without the token `GET /b`
answers `404` — try it. Humans hitting `GET /` always get branch A.

> The default mode is `strict` — in it `POST /ai-token` does not exist at all
> (a uniform `404`), and only RFC 9421 signatures open branch B. Set
> `TARELGO_CAPTCHAI_MODE=best_effort` to play with tokens, as above.

## 📦 Production installation (Ubuntu 24.04)

CaptchAI is built for a **plain multi-service VPS**: it coexists with your
existing nginx, Apache and database, listens internally on the free port
**8008** and adds **zero** extra infrastructure — no Docker, no Redis, no
message queues. Externally it is just a normal site on standard ports 80/443.

### Prerequisites

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git rsync openssl
```

Your existing PostgreSQL **or** MariaDB is enough — CaptchAI speaks both.
You can also start without a database at all (in-memory mode) and attach one later.

### Option A — one-command installer (recommended)

```bash
git clone https://github.com/TarelGo/tarelgo-captchai.git
cd tarelgo-captchai
sudo bash deploy/install.sh postgres   # or: mariadb | memory
```

The installer:

1. creates a dedicated system user `tarelgo-captchai` (no login shell);
2. deploys the code to `/opt/tarelgo-captchai` with an isolated venv;
3. generates `/opt/tarelgo-captchai/.env` with fresh secrets
   (an existing `.env` is preserved — safe to re-run);
4. creates the database schema (`tarelgo_*` tables) automatically on first start;
5. installs and starts the **hardened systemd unit** listening on
   `127.0.0.1:8008` (non-root, `NoNewPrivileges`, `ProtectSystem=strict`,
   `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, no capabilities).

Verify:

```bash
curl -s http://127.0.0.1:8008/healthz
# {"status":"ok","service":"TarelGo CaptchAI","version":"1.0.0","mode":"...","storage":true}
```

### Option B — manual step-by-step

<details>
<summary><b>Click to expand the full manual walkthrough</b></summary>

```bash
# 1. Dedicated system user
sudo useradd --system --home /opt/tarelgo-captchai \
             --shell /usr/sbin/nologin tarelgo-captchai

# 2. Code + virtualenv
sudo git clone https://github.com/TarelGo/tarelgo-captchai.git /opt/tarelgo-captchai
cd /opt/tarelgo-captchai
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install ".[postgres]"      # or ".[mariadb]" or "."

# 3. Configuration
sudo cp .env.example /opt/tarelgo-captchai/.env
sudo openssl rand -base64 36 | tr -d '\n' | tr '/+' '_-'   # your secret
sudoedit /opt/tarelgo-captchai/.env

# 4. Database (pick ONE; schema is created automatically on first start)
sudo -u postgres psql -c "CREATE USER tarelgo WITH PASSWORD 'CHANGE_ME';"
sudo -u postgres psql -c "CREATE DATABASE tarelgo_captchai OWNER tarelgo;"
#   -> TARELGO_CAPTCHAI_DB_DSN=postgresql://tarelgo:CHANGE_ME@127.0.0.1:5432/tarelgo_captchai
# or, for MariaDB:
#   CREATE USER 'tarelgo'@'localhost' IDENTIFIED BY 'CHANGE_ME';
#   CREATE DATABASE tarelgo_captchai;
#   GRANT ALL ON tarelgo_captchai.* TO 'tarelgo'@'localhost';
#   -> TARELGO_CAPTCHAI_DB_DSN=mysql://tarelgo:CHANGE_ME@127.0.0.1:3306/tarelgo_captchai

# 5. Ownership and systemd unit
sudo chown -R tarelgo-captchai:tarelgo-captchai /opt/tarelgo-captchai
sudo cp deploy/tarelgo-captchai.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tarelgo-captchai
systemctl status tarelgo-captchai --no-pager

# 6. Health check
curl -s http://127.0.0.1:8008/healthz
```

</details>

### Database choice

| Backend | DSN scheme | Extra | When to pick |
|---|---|---|---|
| PostgreSQL | `postgresql://user:pass@host:5432/db` | `pip install .[postgres]` | already on the VPS, production default |
| MariaDB | `mysql://user:pass@host:3306/db` | `pip install .[mariadb]` | already on the VPS, same features |
| In-memory | — | set `TARELGO_CAPTCHAI_ALLOW_MEMORY=true` | dev/test only, single process |

Dialect detection is automatic: the DSN scheme decides, drivers are optional
extras, all tables are prefixed `tarelgo_` and created automatically.

## 🔀 Proxy topologies

The app is **proxy-agnostic**: pass `Host` and `X-Forwarded-*` headers and
keep `TARELGO_CAPTCHAI_TRUSTED_PROXIES` in sync — that is all. Four supported
topologies, ready-made configs included:

| Topology | Config files |
|---|---|
| nginx → Apache → uvicorn:8008 *(your current chain)* | `deploy/nginx_front_tarelgo.conf` + `deploy/apache_tarelgo_vhost.conf` |
| nginx only → uvicorn:8008 | `deploy/nginx_only_tarelgo.conf` |
| Apache only → uvicorn:8008 | `deploy/apache_only_tarelgo_vhost.conf` |
| Direct (no proxy at all) | run with `TARELGO_CAPTCHAI_BIND_HOST=0.0.0.0` |

**Port 8008 is internal** — bind it to loopback and never open it in the
firewall. Visitors always see the standard `https://your-domain` on 443.
Switching topologies later (say, dropping Apache) is a config-file swap,
not a code change: the fork logic reads forwarded headers only from
**trusted proxy hops**, so spoofing a client IP requires *being* a trusted proxy.

Enable a topology (nginx example):

```bash
sudo cp deploy/nginx_only_tarelgo.conf /etc/nginx/sites-available/tarelgo-captchai.conf
sudo ln -s /etc/nginx/sites-available/tarelgo-captchai.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## ⚙️ Configuration

Everything is one environment-variable namespace `TARELGO_CAPTCHAI_*` —
safe on a shared VPS, zero collisions with your other services. See
[`.env.example`](.env.example) for the fully annotated list.

| Variable | Default | Description |
|---|---|---|
| `MODE` | `strict` | `strict` — RFC 9421 only; `best_effort` — tokens additionally |
| `SECRETS` | — | comma-separated HMAC secrets; **first = active**, rest stay valid during rotation |
| `TOKEN_TTL` | `120` | capability token lifetime, seconds |
| `TOKEN_BIND_UA` | `true` | bind tokens to the SHA-256 of the User-Agent |
| `THRESHOLD` | `3` | minimal score for the token gate |
| `RATELIMIT_AI_TOKEN` | `5/600` | token requests per IP per window; excess → `429` + ban |
| `BAN_SECONDS` | `900` | ban duration after rate-limit abuse (15 min) |
| `DB_DSN` | — | `postgresql://…` **or** `mysql://…` — the scheme picks the driver |
| `ALLOW_MEMORY` | `false` | allow in-memory storage (dev only) |
| `TRUSTED_PROXIES` | `127.0.0.1/32,::1/128` | CIDR list of hops allowed to set `X-Forwarded-For` |
| `WBA_MAX_AGE` / `WBA_CLOCK_SKEW` | `600` / `5` | signature freshness window / clock tolerance, seconds |
| `WBA_DIRECTORY_TTL` | `3600` | agent key-directory cache, seconds |
| `WBA_ALLOW_PRIVATE_KEYHOST` | `false` | **never enable in production** (SSRF protection) |
| `BIND_HOST` / `BIND_PORT` | `127.0.0.1` / `8008` | internal listener |
| `METRICS_PRIVATE_ONLY` | `true` | `/metrics` visible to trusted proxies only |

Secret rotation: append the new secret to `SECRETS`, restart, retire the old
one later — tokens signed by the previous secret keep working during the
overlap window, so nobody gets logged out.

## 🔌 API reference

| Route | Purpose |
|---|---|
| `GET /` | **the fork**: branch A page, or branch B content for signed agents |
| `POST /ai-token` | capability token after scoring (`best_effort` only) |
| `GET /b` | AI-only branch (strict: signature; best_effort: token or signature) |
| `GET /healthz` | `{"status":"ok","mode":…,"storage":true}` |
| `GET /metrics` | Prometheus text format (trusted proxies only by default) |
| `GET /robots.txt` | crawler policy — `Disallow: /b` |
| `GET /llms.txt` | machine-readable policy and auth guide for AI agents |

Every response carries `X-TarelGo-Branch: A|B` — a handy assertion for
integration tests. Response bodies never leak *why* something was rejected:
there is exactly one `404`, everywhere, forever.

### curl cookbook

```bash
# Humans and unknown clients -> branch A (HTML), always 200
curl -s https://your-site/ -D- -o /dev/null | grep X-TarelGo-Branch   # -> A

# Agent in best_effort mode: mint a one-shot token
curl -s -X POST https://your-site/ai-token \
  -H 'User-Agent: Mozilla/5.0 (compatible; MyAIAgent/1.0; +https://myagent.example)'
# -> {"token":"tg1.0.<nonce>.<exp>.<hmac>","token_type":"capability","expires_in":120}

# Spend the token on the AI-only branch (same User-Agent: tokens are UA-bound)
curl -s https://your-site/b \
  -H 'User-Agent: Mozilla/5.0 (compatible; MyAIAgent/1.0; +https://myagent.example)' \
  -H 'Authorization: Bearer tg1.0.<nonce>.<exp>.<hmac>'

# The alternative header also works:  -H 'x-tarelgo-token: tg1.0.…'
# Health check
curl -s https://your-site/healthz

# Rate-limited abuse answers:
#   429 + Retry-After during the window, then a 15-minute ban.
```

Token anatomy — `tg1.<key-index>.<nonce>.<exp>.<base64url(HMAC-SHA256)>`,
bound to client IP, UA hash and (optionally) JA3, single-use, checked with
`hmac.compare_digest` in constant time.

## 🤖 For AI agents

Ship [`examples/agent_client.py`](examples/agent_client.py) as the reference
client — it implements both flows end to end:

```bash
python examples/agent_client.py --base-url https://your-site --best-effort

python examples/agent_client.py --base-url https://your-site --strict \
    --key key.pem --agent-uri https://agent.example
```

Publish your agent keys at
`https://<you>/.well-known/http-message-signatures-directory` (JWKS) and
sign requests with the covered components
`@method @path @authority content-digest` — the `Signature-Agent` header
is required and must be covered by the signature. Fetch
[`/llms.txt`](https://tarelgo.com/llms.txt) first: it is written for you.

## 🧪 Testing & development

```bash
pip install -e ".[postgres,mariadb,dev]"
pytest              # 72 tests: detection, tokens, RFC vectors, access, e2e
ruff check .        # lint clean
```

The suite includes the RFC 8037 Appendix A.3 Ed25519 JWK-thumbprint
known-answer vector, an exact RFC 9421 §2.5 signature-base literal, and
12 end-to-end scenarios covering both modes — including the spec's killer
requirement: *a human who knows the URL, the algorithm and the headers
still cannot open branch B*.

Optional load markers are excluded by default (`pytest -m perf` runs them).

## 📁 Project structure

```
tarelgo-captchai/
├── deploy/                  # production-ready configs for a plain VPS
│   ├── install.sh           #   one-command installer (postgres|mariadb|memory)
│   ├── tarelgo-captchai.service  # hardened systemd unit
│   ├── nginx_front_tarelgo.conf  # nginx → Apache → app
│   ├── nginx_only_tarelgo.conf   # nginx → app
│   └── apache_*_tarelgo_vhost.conf  # Apache topologies
├── examples/
│   └── agent_client.py      # reference AI-agent client (both flows)
├── src/tarelgo_captchai/
│   ├── main.py              # FastAPI app factory
│   ├── router.py            # the fork: /, /ai-token, /b, /healthz, /metrics …
│   ├── config.py            # TARELGO_CAPTCHAI_* settings (pydantic-settings)
│   ├── detect/              # scoring, browser-claim signals, JA3
│   ├── webbotauth/          # RFC 9421: sfv, signature base, keys, directory, verify
│   ├── tokens.py            # one-shot capability tokens
│   ├── ratelimit.py         # 5/600 window + 15-min ban
│   ├── storage.py           # PostgreSQL / MariaDB / memory, tarelgo_* schema
│   ├── security.py          # compare_digest, XFF trust, SSRF guard
│   ├── content.py           # branch A / branch B payloads
│   ├── metrics.py           # Prometheus text
│   └── logging.py           # JSON logs without PII
├── tests/                   # 72 tests, 5 files + conftest
├── .env.example             # fully annotated configuration
└── pyproject.toml
```

## 🛡️ Security design

- HMAC comparisons strictly via `hmac.compare_digest`; tokens are
  single-use, IP/UA/JA3-bound, TTL 120 s.
- Secret rotation with overlap — old tokens stay valid during rotation.
- Uniform `404` for every branch-B rejection (identical body, status,
  headers) — no oracle, no endpoint discovery.
- `X-Forwarded-For` resolved only through trusted proxy hops.
- JSON logs without PII: no bodies, no `Authorization`, no cookies, no raw
  User-Agent (SHA-256 only); forbidden keys stripped in the formatter.
- Decision journal in the database with configurable retention.
- SSRF guard on directory fetches: https only, 2 s timeout, 64 KiB cap,
  private addresses blocked, negative cache.
- systemd sandbox: non-root, `NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, no caps.
- Fail-open on branch A, fail-closed on branch B — a storage outage never
  leaks the AI branch, and never takes the human site down.

## ⚡ Performance

Single-process uvicorn, no ORM, pre-rendered payloads, constant-time HMAC
math. Budgets from the spec: p99 `GET /` < 20 ms, `GET /b` < 30 ms — both
are met with a wide margin on a modest VPS. The first request of an unknown
signed agent costs one cached-or-fetched directory lookup (2 s worst case,
once per agent per hour); everything else is cache hits. Scale by adding
workers behind the same PostgreSQL/MariaDB store.

## 🗺️ Roadmap

- [x] RFC 9421 Web Bot Auth (strict mode)
- [x] One-shot capability tokens with rotation (best-effort mode)
- [x] PostgreSQL / MariaDB dual dialect
- [x] Hardened systemd deployment for a shared VPS
- [ ] JA4 fingerprints alongside JA3
- [ ] Prometheus dashboard examples
- [ ] Managed dashboard at [tarelgo.com](https://tarelgo.com)

## 🤝 Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).
Run `pytest` and `ruff check .` locally before submitting; CI must stay
green. Security reports: please use
[GitHub Security Advisories](https://github.com/TarelGo/tarelgo-captchai/security/advisories/new)
rather than public issues.

## 📄 License

Released under the [MIT License](LICENSE) — free for commercial and
personal use. © 2026 TarelGo Development.

## 🔗 Links

| | |
|---|---|
| 🌐 Website | [https://tarelgo.com](https://tarelgo.com) |
| 🎯 CaptchAI demo | [https://tarelgo.com](https://tarelgo.com#captchai-demo) |
| 𝕏 / Twitter | [@TarelGoOfficial](https://x.com/TarelGoOfficial) |
| 💬 Telegram | [t.me/TarelGoCoin](https://t.me/TarelGoCoin) |
| 🐙 GitHub | [github.com/TarelGo](https://github.com/TarelGo) |

## 📚 References

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) — HTTP Message Signatures
- [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) — Structured Field Values for HTTP
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530) — Digest Fields
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) / [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037) — JWK Thumbprints / OKP keys
- [`draft-meunier-webbotauth-httpsig-protocol`](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/) — Web Bot Auth protocol
- [`draft-meunier-webbotauth-registry`](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-registry/) — Signature Agent cards

---

<div align="center">

**TarelGo CaptchAI** — built with 🎯 by [TarelGo Development](https://tarelgo.com)

*If this project saved you from CAPTCHA hell, give it a ⭐*

</div>
