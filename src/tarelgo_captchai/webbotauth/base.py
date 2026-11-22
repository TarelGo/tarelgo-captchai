"""Signature base construction per RFC 9421 (section 2.5) for TarelGo CaptchAI.

Shared by the verifier (webbotauth/verify.py) and the example agent
(examples/agent_client.py). Correctness is confirmed by a test against the
official RFC 9421 test vector (Appendix B.2.6, Ed25519).

ABNF: signature-base = *( signature-base-line LF ) signature-params-line -
every component line ends with LF; the @signature-params line does NOT.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from .sfv import (
    SfError,
    SfToken,
    sf_parse_dictionary,
    sf_serialize_bare_item,
    sf_serialize_params,
)

SUPPORTED_DERIVED = ("@method", "@path", "@authority", "@query", "@target-uri")
SIGNATURE_PARAMS_ID = "@signature-params"


@dataclass(slots=True)
class RequestParts:
    """Normalized HTTP request parts for signature base construction."""

    method: str        # as sent (uppercase for standard methods)
    scheme: str        # lowercase: http/https (after trusted proxies)
    authority: str     # host:port, lowercase, default port removed
    path: str          # absolute path WITHOUT query, percent-encoding preserved
    query: str         # "?query" or "?" when empty
    target_uri: str    # scheme://authority/path?query
    fields: dict[str, list[str]] = field(default_factory=dict)  # lower name -> values


def normalize_authority(host: str, scheme: str) -> str:
    """RFC 9421 section 2.2.3: hostname lowercase, default port removed."""
    host = (host or "").strip().lower()
    if not host:
        return host
    if host.startswith("["):  # IPv6 [::1]:8008
        closing = host.find("]")
        if closing != -1 and ":" in host[closing + 1:]:
            host_part, port = host[: closing + 1], host[closing + 1:]
        else:
            return host
    elif ":" in host:
        host_part, _, port = host.partition(":")
    else:
        return host
    if port.lstrip("+").isdigit():
        if (scheme == "http" and int(port) == 80) or (
            scheme == "https" and int(port) == 443
        ):
            return host_part
        return f"{host_part}:{port}"
    return host


def derive_component_value(name: str, params: dict, parts: RequestParts) -> str:
    """Component value (derived component or HTTP field) per RFC 9421 sections 2.1-2.2."""
    if name.startswith("@"):
        if params:
            raise ValueError(f"derived component {name} does not accept parameters")
        if name == "@method":
            return parts.method
        if name == "@path":
            return parts.path or "/"
        if name == "@authority":
            return parts.authority
        if name == "@query":
            return parts.query or "?"
        if name == "@target-uri":
            return parts.target_uri
        raise ValueError(f"unknown derived component: {name}")

    values = parts.fields.get(name.lower())
    if not values:
        raise ValueError(f"field is missing from the request: {name}")
    if params:
        key = params.get("key")
        if set(params) - {"key"} or not isinstance(key, str):
            raise ValueError(f"field {name}: only the 'key' parameter is supported")
        member_value, member_params = _dictionary_member(values, key)
        return sf_serialize_bare_item(member_value) + sf_serialize_params(member_params)
    # multiple lines of one field: joined in arrival order with ", "
    return ", ".join(v.strip() for v in values)


def _dictionary_member(values: list[str], key: str):  # type: ignore[no-untyped-def]
    raw = ", ".join(v.strip() for v in values)
    try:
        dictionary = sf_parse_dictionary(raw)
    except SfError as exc:
        raise ValueError(f"field is not a valid Dictionary: {exc}") from exc
    if key not in dictionary:
        raise ValueError(f"no member {key} in the Dictionary")
    member_value, member_params = dictionary[key]
    if member_value is True and not member_params:
        return SfToken(key), {}
    return member_value, member_params


def build_signature_base(
    covered: list[tuple[str, dict]], parts: RequestParts, params_value: str
) -> bytes:
    """Assemble the signature base; covered is [(name, params)] in signing order."""
    lines: list[str] = []
    seen: set[tuple[str, frozenset]] = set()
    for name, params in covered:
        identifier = (name, frozenset(params.items()))
        if identifier in seen:
            raise ValueError(f"component {name} is listed twice")
        seen.add(identifier)
        value = derive_component_value(name, params, parts)
        ident_serialized = sf_serialize_bare_item(name) + sf_serialize_params(params)
        lines.append(f"{ident_serialized}: {value}")
    lines.append(f'"@signature-params": {params_value}')
    base = "\n".join(lines)
    try:
        return base.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("signature base contains non-ASCII characters") from exc


def parse_covered_components(
    inner_items: list[tuple[object, dict]], require_method_path: bool
) -> tuple[list[tuple[str, dict]], str]:
    """Parse covered components from Signature-Input; return (covered, summary).

    Validates: string component names, supported derived components, the
    bare @authority/@target-uri host binding and (per spec) @method + @path.
    """
    covered: list[tuple[str, dict]] = []
    for value, params in inner_items:
        if isinstance(value, SfToken):
            raise ValueError("component name must be a string (sf-string), not a token")
        if not isinstance(value, str):
            raise ValueError("component name must be a string")
        if value.startswith("@"):
            if params:
                raise ValueError(f"derived component {value} does not accept parameters")
            if value not in SUPPORTED_DERIVED:
                raise ValueError(f"unsupported derived component: {value}")
        else:
            unknown = set(params) - {"key"}
            if unknown:
                raise ValueError(
                    f"field {value}: unsupported parameters {sorted(unknown)}"
                )
            key_param = params.get("key")
            if "key" in params and not isinstance(key_param, str):
                raise ValueError(f"field {value}: the 'key' parameter must be a string")
        covered.append((value, dict(params)))

    names = [n for n, _p in covered]
    if not ("@authority" in names or "@target-uri" in names):
        raise ValueError(
            "the signature must cover @authority or @target-uri (host binding)"
        )
    if require_method_path and ("@method" not in names or "@path" not in names):
        raise ValueError(
            "the signature must cover @method and @path (TarelGo CaptchAI profile)"
        )
    return covered, ", ".join(names)


def coverage_covers_agent(
    covered: list[tuple[str, dict]],
    header_kind: str,
    agent_label: str,
) -> bool:
    """Does the signature cover the Signature-Agent header (current/legacy form)?"""
    agent_components = [(n, p) for n, p in covered if n.lower() == "signature-agent"]
    if header_kind == "current":
        matching = [
            (n, p)
            for n, p in agent_components
            if isinstance(p.get("key"), str) and set(p) == {"key"}
        ]
        return any(p.get("key") == agent_label for _, p in matching)
    # legacy: plain string value, covered without parameters
    return any(set(p) == set() for _, p in agent_components)


def field_values_map(
    headers: Mapping[str, str] | list[tuple[str, str]]
) -> dict[str, list[str]]:
    """Build a multimap of fields (in arrival order) from request headers."""
    fields: dict[str, list[str]] = {}
    if isinstance(headers, Mapping):
        items = [(k, v) for k, v in headers.items()]
    else:
        items = list(headers)
    for name, value in items:
        fields.setdefault(name.lower(), []).append(value)
    return fields
