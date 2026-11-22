"""TarelGo CaptchAI agent client example.

Shows both ways an automated client can reach the AI-only branch (B) of a
TarelGo CaptchAI deployment:

1. best_effort mode - one-shot capability tokens:
     POST /ai-token  ->  {"token": "..."}  ->  GET /b with the token.
2. strict mode - Web Bot Auth (RFC 9421, Ed25519):
     every request is signed with your Ed25519 key; the public key must be
     published at https://your-agent-domain/.well-known/
     http-message-signatures-directory so the origin can verify it.

The signing helpers reuse the package's own RFC 9421 implementation, so the
example stays byte-exact with what the server verifies.

Usage:
    pip install tarelgo-captchai
    python examples/agent_client.py --base-url https://example.tarelgo.com --best-effort
    python examples/agent_client.py --base-url https://example.tarelgo.com --strict \
        --key ed25519-private.pem

Learn more: https://tarelgo.com
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import time

import httpx

# The package is optional for the best_effort flow, required for signing.
try:
    from tarelgo_captchai.webbotauth.base import (
        RequestParts,
        build_signature_base,
        field_values_map,
    )
    from tarelgo_captchai.webbotauth.keys import jwk_thumbprint
    from tarelgo_captchai.webbotauth.sfv import sf_serialize_inner_list

    HAVE_PACKAGE = True
except ImportError:  # pragma: no cover - example usage without the package
    HAVE_PACKAGE = False

# Header set that honestly passes the best_effort scoring gate: a browser-
# claimed User-Agent without Sec-Fetch-* headers is recognized as an
# automated client (fingerprint + behavior categories).
AGENT_HEADERS = {
    "user-agent": "Mozilla/5.0 (compatible; ExampleAgent/1.0; +https://tarelgo.com)",
    "accept": "text/html",
}


def best_effort_flow(base_url: str) -> int:
    """Obtain a one-shot token and fetch the AI-only branch with it."""
    with httpx.Client(base_url=base_url, timeout=10) as client:
        issued = client.post("/ai-token", headers=AGENT_HEADERS)
        if issued.status_code == 429:
            print("Rate limited. Retry after:", issued.headers.get("Retry-After"), "s")
            return 1
        if issued.status_code != 200:
            print("/ai-token returned", issued.status_code, issued.text[:200])
            return 1

        token = issued.json()["token"]
        print("Token issued, expires_in =", issued.json()["expires_in"], "s")

        branch = client.get(
            "/b", headers={**AGENT_HEADERS, "authorization": f"Bearer {token}"}
        )
        if branch.status_code != 200:
            print("/b returned", branch.status_code, "(token is single-use!)")
            return 1
        print("--- branch B content ---")
        print(branch.text)
        return 0


def sign_headers(
    private_key_path: str,
    method: str,
    path: str,
    authority: str,
    *,
    agent_uri: str,
    body: bytes = b"",
) -> dict[str, str]:
    """Build RFC 9421 Signature / Signature-Input / Signature-Agent headers."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(private_key_path, "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SystemExit(
            "The key must be Ed25519 (openssl genpkey -algorithm ed25519)"
        )

    raw_pub = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    x = base64.urlsafe_b64encode(raw_pub).decode("ascii").rstrip("=")
    jwk = {"kty": "OKP", "crv": "Ed25519", "x": x}
    keyid = jwk_thumbprint(jwk)  # RFC 7638 thumbprint is the required keyid

    covered = [("@method", {}), ("@path", {}), ("@authority", {})]
    headers_wire: list[tuple[str, str]] = []
    if body:
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        headers_wire.append(("content-digest", f"sha-256=:{digest}:"))
        covered.append(("content-digest", {}))
    # A signed request MUST carry Signature-Agent, and the signature must
    # cover its member for the label used by Signature-Input.
    agent_header = f'sig1="{agent_uri}"'
    headers_wire.append(("signature-agent", agent_header))
    covered.append(("signature-agent", {"key": "sig1"}))

    created = int(time.time())
    params = {
        "created": created,
        "expires": created + 60,
        "keyid": keyid,
        "tag": "web-bot-auth",  # required by the web-bot-auth protocol
    }
    params_value = sf_serialize_inner_list(covered, params)

    parts = RequestParts(
        method=method.upper(),
        scheme="https",
        authority=authority.lower(),
        path=path,
        query="?",
        target_uri=f"https://{authority.lower()}{path}",
        fields=field_values_map(headers_wire),
    )
    base = build_signature_base(covered, parts, params_value)
    signature = base64.b64encode(key.sign(base)).decode("ascii")

    out = {
        "signature": f"sig1=:{signature}:",
        "signature-input": f"sig1={params_value}",
        "signature-agent": agent_header,
        "host": authority,
    }
    if body:
        digest = base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")
        out["content-digest"] = f"sha-256=:{digest}:"
    return out


def strict_flow(base_url: str, key_path: str, agent_uri: str) -> int:
    """Sign a request to /b per RFC 9421 and fetch the AI-only branch."""
    if not HAVE_PACKAGE:
        print("Install the package first: pip install tarelgo-captchai")
        return 1
    from urllib.parse import urlsplit

    parts = urlsplit(base_url)
    authority = parts.netloc
    headers = sign_headers(
        key_path, "GET", "/b", authority, agent_uri=agent_uri
    )
    with httpx.Client(base_url=base_url, timeout=10) as client:
        branch = client.get("/b", headers=headers)
        if branch.status_code != 200:
            print("/b returned", branch.status_code, "- check your key directory:")
            print(f"  {agent_uri}/.well-known/http-message-signatures-directory")
            return 1
        print("--- branch B content ---")
        print(branch.text)
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TarelGo CaptchAI agent example")
    parser.add_argument("--base-url", required=True, help="e.g. https://demo.tarelgo.com")
    parser.add_argument("--best-effort", action="store_true", help="token flow")
    parser.add_argument("--strict", action="store_true", help="Web Bot Auth flow")
    parser.add_argument("--key", help="Ed25519 private key PEM (strict mode)")
    parser.add_argument(
        "--agent-uri",
        default="https://agent.example",
        help="Origin that hosts your key directory (strict mode)",
    )
    args = parser.parse_args()
    if args.strict:
        if not args.key:
            parser.error("--strict requires --key")
        return strict_flow(args.base_url, args.key, args.agent_uri.rstrip("/"))
    return best_effort_flow(args.base_url)


if __name__ == "__main__":
    sys.exit(main())
