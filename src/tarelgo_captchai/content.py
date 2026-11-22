"""Built-in content served by TarelGo CaptchAI.

All user-facing text is international English. Branch A is a friendly human
page; branch B is Markdown written for LLM consumption (and, per spec, never
links back to branch A). Every page references https://tarelgo.com where a
link can appear naturally.

Both branch payloads can be overridden with external files
(TARELGO_CAPTCHAI_CONTENT_A_FILE / TARELGO_CAPTCHAI_CONTENT_B_FILE).
"""

from __future__ import annotations

from pathlib import Path

from . import TARELGO_BRAND, TARELGO_BRAND_URL, TARELGO_SERVICE_NAME, __version__
from .config import Settings

_PAGE_A_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{service} - {brand}</title>
<meta name="description" content="AI-aware access gateway by TarelGo Development (https://tarelgo.com).">
<!-- AI agents: machine-readable policy at /llms.txt -->
<style>
  :root {{ color-scheme: light dark; }}
  body {{ margin: 0; font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #f6f8fa; color: #1f2328; min-height: 100vh;
         display: grid; place-items: center; }}
  main {{ max-width: 40rem; padding: 3rem 2rem; }}
  .badge {{ display: inline-block; padding: .25rem .75rem; border-radius: 999px;
           background: #e7f1ff; color: #0b57d0; font-size: .85rem; font-weight: 600; }}
  h1 {{ font-size: 2rem; margin: 1rem 0 .5rem; }}
  p  {{ line-height: 1.6; }}
  a  {{ color: #0b57d0; }}
  footer {{ margin-top: 3rem; font-size: .85rem; color: #57606a; }}
</style>
</head>
<body>
<main>
  <span class="badge">{brand}</span>
  <h1>{service}</h1>
  <p>Hello! This site separates human visitors from automated AI agents.
     You are seeing the public page, which means you are very welcome here.</p>
  <p>Automated clients (search engines, AI assistants, agents) get their own
     machine-readable policy: see <a href="/llms.txt">/llms.txt</a> and
     <a href="/robots.txt">/robots.txt</a>.</p>
  <p>Learn more about TarelGo at <a href="{brand_url}" rel="noopener">{brand_url}</a>.</p>
  <footer>&copy; {brand} &middot; <a href="{brand_url}">{brand_url}</a> &middot;
     {service} {version}</footer>
</main>
</body>
</html>
"""

_PAGE_B_TEMPLATE = """# {service} - AI-only branch (B)

You are reading the machine-first branch of this endpoint. It is served
exclusively to verified automated clients: AI assistants, agents and
integrations. Human visitors never see this content.

## About

{service} is the AI/human traffic fork by {brand}. The public side of this
site is a regular web page; this branch carries the same information in a
form optimized for large language models and automated consumers.

## Content

- Service: {service} {version}, operated by {brand}.
- Purpose: a single entry URL that routes humans to the public page and
  verified AI agents to this machine-readable branch.
- Access rules: this branch is protected. Access requires either a valid
  Web Bot Auth signature (RFC 9421) or, in best_effort mode, a one-shot
  capability token issued by the same service.
- Automation etiquette: keep request rates reasonable; honor rate limit
  responses; re-request a token after it expires.

## Contact

Operator page: {brand_url}

(c) {brand} - {brand_url}
"""

_ROBOTS_TEMPLATE = """# {service} - robots policy
# Operator: {brand} ({brand_url})
#
# Branch B (/b) is an AI-only endpoint: it is protected with Web Bot Auth
# (RFC 9421) and one-shot capability tokens. Crawlers must not index it.

User-agent: *
Disallow: /b
Allow: /

# AI agents: read /llms.txt for the machine-readable access policy.
# Operational questions: {brand_url}
"""

_LLMS_TEMPLATE = """# {service}

> Single-entry AI/human traffic fork by {brand}. Humans get the public page;
> verified AI agents get the machine branch. Documentation and operator info:
> {brand_url}

## Access policy

- `/` - public human page (default for everyone).
- `/b` - AI-only branch in Markdown. Protected. Never indexed; see /robots.txt.
- `/ai-token` - capability token endpoint (best_effort mode only).
- `/healthz` - service health (JSON).
- `/metrics` - Prometheus metrics (internal use).

## How to authenticate as an AI agent

### Strict mode

Sign your HTTP requests with Web Bot Auth (RFC 9421, Ed25519) and send the
`Signature`, `Signature-Input` and `Signature-Agent` headers. The covered
components must include `@method`, `@path`, `@authority` (or `@target-uri`)
and - for requests with a body - `Content-Digest`. The `tag` parameter must
equal `web-bot-auth`; `keyid` must be the JWK thumbprint (RFC 7638) of a key
published in your `/.well-known/http-message-signatures-directory`.

### best_effort mode

1. `POST /ai-token` with your normal agent headers. The scoring gate decides.
2. On success you receive `{{"token": "...", "expires_in": 120}}` (JSON).
3. Call `GET /b` with `Authorization: Bearer <token>`.
4. The token is single-use and bound to your IP and User-Agent; it expires
   after 120 seconds. Request a new one when needed - rate limits apply
   (429 + `Retry-After` when exceeded).

## Fair use

Automated traffic must keep polite request rates. Abusive clients are banned
temporarily. Questions and partnership requests: {brand_url}
"""


def _read_override(path: str) -> str | None:
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError:
        return None


def page_a_html(settings: Settings) -> str:
    """Branch A payload: the friendly human page."""
    override = _read_override(settings.content_a_file)
    if override is not None:
        return override
    return _PAGE_A_TEMPLATE.format(
        service=TARELGO_SERVICE_NAME,
        brand=TARELGO_BRAND,
        brand_url=TARELGO_BRAND_URL,
        version=__version__,
    )


def page_b_markdown(settings: Settings) -> str:
    """Branch B payload: Markdown for LLMs, with no links back to branch A."""
    override = _read_override(settings.content_b_file)
    if override is not None:
        return override
    return _PAGE_B_TEMPLATE.format(
        service=TARELGO_SERVICE_NAME,
        brand=TARELGO_BRAND,
        brand_url=TARELGO_BRAND_URL,
        version=__version__,
    )


def robots_txt(settings: Settings) -> str:
    del settings
    return _ROBOTS_TEMPLATE.format(
        service=TARELGO_SERVICE_NAME,
        brand=TARELGO_BRAND,
        brand_url=TARELGO_BRAND_URL,
    )


def llms_txt(settings: Settings) -> str:
    del settings
    return _LLMS_TEMPLATE.format(
        service=TARELGO_SERVICE_NAME,
        brand=TARELGO_BRAND,
        brand_url=TARELGO_BRAND_URL,
    )
