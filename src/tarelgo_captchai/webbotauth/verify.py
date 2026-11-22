"""Web Bot Auth verification (RFC 9421 + web-bot-auth) for TarelGo CaptchAI.

The TarelGo CaptchAI strict profile (spec 6.1):
  - required headers: Signature + Signature-Input;
  - tag = "web-bot-auth", alg = ed25519 (or absent - the key is Ed25519);
  - required signature parameters: created, keyid; expires checked if present;
  - the signature must cover a bare @authority or @target-uri (host binding)
    and, per spec, @method and @path (TARELGO_CAPTCHAI_WBA_REQUIRE_METHOD_PATH);
  - a request body implies a covered content-digest that must verify;
  - if the agent sends Signature-Agent, the signature must cover it
    (TARELGO_CAPTCHAI_WBA_REQUIRE_AGENT makes the header mandatory - the
    protocol draft says a signed request MUST carry it);
  - freshness: created is not older than TARELGO_CAPTCHAI_WBA_MAX_AGE seconds;
  - keys come from the agent directory (CIMD/legacy); kid/thumbprint = keyid.

Any error raises WbaError; the router answers with the uniform 404.
"""

from __future__ import annotations

import binascii
import hashlib
import time
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature

from ..config import Settings
from .base import (
    RequestParts,
    build_signature_base,
    coverage_covers_agent,
    field_values_map,
    normalize_authority,
    parse_covered_components,
)
from .directory import AgentEntry, AgentKeyError, AgentKeyResolver
from .keys import jwk_public_key
from .sfv import (
    SfError,
    SfToken,
    sf_parse_dictionary,
    sf_parse_item,
    sf_serialize_inner_list,
)

WBA_TAG = "web-bot-auth"
WBA_ALG = "ed25519"


class WbaError(Exception):
    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


@dataclass(slots=True)
class WbaResult:
    keyid: str
    agent_uri: str | None
    label: str
    nonce: str | None
    created: int


@dataclass(slots=True)
class VerifyInput:
    method: str
    scheme: str
    host: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: bytes = b""


def parse_signature_agent(raw: str) -> tuple[str, list[AgentEntry]]:
    """Parse Signature-Agent: current (Dictionary) or legacy (Item) form.

    Returns (kind, entries); kind is 'current' | 'legacy'.
    """
    try:
        dictionary = sf_parse_dictionary(raw)
        entries: list[AgentEntry] = []
        for label, (value, params) in dictionary.items():
            if not isinstance(value, str):
                raise WbaError(
                    "invalid_agent", "Signature-Agent values must be strings"
                )
            ptype = params.get("type")
            if params and not (
                len(params) == 1 and isinstance(ptype, SfToken) and str(ptype) == "cimd"
            ):
                continue
            _validate_agent_uri(value)
            entries.append(AgentEntry(label=label, uri=value, cimd=ptype is not None))
        if not entries:
            raise WbaError("invalid_agent", "no acceptable Signature-Agent members")
        return "current", entries
    except WbaError:
        raise
    except SfError as dictionary_error:
        try:
            value, _params = _parse_item_checked(raw)
            _validate_agent_uri(value)
            return "legacy", [AgentEntry(label="", uri=value)]
        except WbaError:
            raise
        except SfError as item_error:
            raise WbaError(
                "invalid_agent",
                f"Signature-Agent not recognized: {dictionary_error}; {item_error}",
            ) from item_error


def _parse_item_checked(raw: str) -> tuple[str, dict]:  # type: ignore[type-arg]
    value, params = sf_parse_item(raw)
    if not isinstance(value, str):
        raise WbaError("invalid_agent", "legacy Signature-Agent must be a string")
    if params:
        raise WbaError("invalid_agent", "legacy Signature-Agent carries no parameters")
    return value, params


def _validate_agent_uri(uri: str) -> None:
    if not uri.startswith("https://"):
        raise WbaError("invalid_agent", "the agent URI must be https")


async def verify_web_bot_auth(
    payload: VerifyInput,
    resolver: AgentKeyResolver,
    settings: Settings,
    now: int | None = None,
) -> WbaResult:
    """Full Web Bot Auth verification for a branch B request."""
    headers_map = field_values_map(payload.headers)
    single = {name: values[0] for name, values in headers_map.items() if values}

    sig_input_raw = single.get("signature-input")
    sig_raw = single.get("signature")
    if not sig_input_raw or not sig_raw:
        raise WbaError("missing_signature_headers")

    # --- 1. Signature-Input ---------------------------------------------------
    try:
        sig_dict = sf_parse_dictionary(sig_input_raw)
    except SfError as exc:
        raise WbaError("invalid_signature_input", str(exc)) from exc
    label, inner_items, params = _select_signature(sig_dict)
    if not isinstance(inner_items, list):
        raise WbaError("invalid_signature_input", "expected an Inner List")

    # --- 2. Signature ----------------------------------------------------------
    try:
        sig_values = sf_parse_dictionary(sig_raw)
    except SfError as exc:
        raise WbaError("invalid_signature", str(exc)) from exc
    if label not in sig_values:
        raise WbaError("signature_label_mismatch")
    sig_value, _sig_params = sig_values[label]
    if not isinstance(sig_value, bytes):
        raise WbaError("invalid_signature", "value is not a Byte Sequence")

    # --- 3. Signature parameters --------------------------------------------------
    keyid = params.get("keyid")
    tag = params.get("tag")
    created = params.get("created")
    expires = params.get("expires")
    alg = params.get("alg")
    nonce = params.get("nonce")

    if not isinstance(keyid, str) or not keyid:
        raise WbaError("missing_keyid")
    if tag != WBA_TAG:
        raise WbaError("bad_tag", "tag must be 'web-bot-auth'")
    if not isinstance(created, int) or isinstance(created, bool):
        raise WbaError("missing_created")
    if expires is not None and not isinstance(expires, int):
        raise WbaError("bad_expires")
    if alg is not None and str(alg) != WBA_ALG:
        raise WbaError("bad_alg", f"only {WBA_ALG} is supported")

    current = now if now is not None else int(time.time())
    if created > current + settings.wba_clock_skew:
        raise WbaError("signature_in_future")
    if current - created > settings.wba_max_age:
        raise WbaError("signature_expired")
    if expires is not None:
        if expires < created:
            raise WbaError("bad_expires", "expires is earlier than created")
        if current > expires + settings.wba_clock_skew:
            raise WbaError("signature_expired")

    # --- 4. Covered components --------------------------------------------------
    try:
        covered, _names = parse_covered_components(
            inner_items, settings.wba_require_method_path
        )
    except ValueError as exc:
        raise WbaError("insufficient_coverage", str(exc)) from exc

    body_present = len(payload.body) > 0 or bool(
        single.get("content-length") and single["content-length"] != "0"
    )
    names = [n for n, _p in covered]
    if body_present and "content-digest" not in names:
        raise WbaError(
            "insufficient_coverage", "the request body is not covered by content-digest"
        )

    # --- 5. Signature-Agent --------------------------------------------------------
    agent_raw = single.get("signature-agent")
    agent_kind: str | None = None
    agent_entries: list[AgentEntry] = []
    agent_label = ""
    if agent_raw:
        agent_kind, agent_entries = parse_signature_agent(agent_raw)
        agent_label = agent_entries[0].label
        if not coverage_covers_agent(covered, agent_kind, agent_label):
            raise WbaError(
                "agent_not_covered", "Signature-Agent is sent but not covered by the signature"
            )
    elif settings.wba_require_agent:
        raise WbaError("missing_agent", "Signature-Agent is required")

    # --- 6. Signature base --------------------------------------------------------------
    fields = field_values_map(payload.headers)
    host = settings.public_authority or payload.host
    authority = normalize_authority(host, payload.scheme)
    if not authority:
        raise WbaError("missing_host")
    path = payload.path or "/"
    query = "?" + payload.query if payload.query else "?"
    target_uri = (
        f"{payload.scheme}://{authority}{path}"
        + (f"?{payload.query}" if payload.query else "")
    )
    parts = RequestParts(
        method=payload.method,
        scheme=payload.scheme,
        authority=authority,
        path=path,
        query=query,
        target_uri=target_uri,
        fields=fields,
    )
    params_value = sf_serialize_inner_list(inner_items, params)
    try:
        base = build_signature_base(covered, parts, params_value)
    except ValueError as exc:
        raise WbaError("base_error", str(exc)) from exc

    # --- 7. content-digest (RFC 9530, sha-256) when a body is present -------------------
    if body_present:
        _verify_content_digest(payload.body, fields)

    # --- 8. Agent key --------------------------------------------------------------------
    try:
        resolved = await resolver.resolve(agent_entries, keyid)
    except AgentKeyError as exc:
        raise WbaError("key_not_found", str(exc)) from exc

    try:
        public_key = jwk_public_key(resolved.jwk)
    except Exception as exc:  # noqa: BLE001
        raise WbaError("bad_key", str(exc)) from exc

    # --- 9. Ed25519 --------------------------------------------------------------------------
    try:
        public_key.verify(sig_value, base)
    except InvalidSignature as exc:
        raise WbaError("bad_signature") from exc
    except (binascii.Error, ValueError) as exc:
        raise WbaError("invalid_signature", str(exc)) from exc

    return WbaResult(
        keyid=keyid,
        agent_uri=resolved.agent_uri,
        label=label,
        nonce=str(nonce) if nonce is not None else None,
        created=created,
    )


def _select_signature(
    sig_dict: dict[str, tuple[Any, dict]],  # type: ignore[type-arg]
) -> tuple[str, Any, dict]:  # type: ignore[type-arg]
    """Select the web-bot-auth signature: by tag, then 'sig1', then the first one."""
    for label, (value, params) in sig_dict.items():
        if params.get("tag") == WBA_TAG:
            return label, value, params
    if "sig1" in sig_dict:
        value, params = sig_dict["sig1"]
        return "sig1", value, params
    for label, (value, params) in sig_dict.items():
        return label, value, params
    raise WbaError("empty_signature_input")


def _verify_content_digest(body: bytes, fields: dict[str, list[str]]) -> None:
    values = fields.get("content-digest")
    if not values:
        raise WbaError("missing_content_digest")
    raw = ", ".join(v.strip() for v in values)
    try:
        digests = sf_parse_dictionary(raw)
    except SfError as exc:
        raise WbaError("invalid_content_digest", str(exc)) from exc
    sha = digests.get("sha-256")
    if sha is None:
        raise WbaError("invalid_content_digest", "no sha-256 entry")
    value, _params = sha
    if not isinstance(value, bytes):
        raise WbaError("invalid_content_digest", "digest is not a Byte Sequence")
    expected = hashlib.sha256(body).digest()
    if value != expected:
        raise WbaError("content_digest_mismatch")
