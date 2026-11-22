"""Minimal HTTP Structured Fields parser/serializer (RFC 8941).

Covers the subset required by TarelGo CaptchAI for RFC 9421: Dictionary,
Item, Inner List, Parameters, String, Token, Integer, Byte Sequence,
Boolean. Strict: any syntax violation raises SfError.

Types are preserved while parsing and reproduced while serializing, so the
canonical re-serialization of Signature-Input matches what the agent signed
(the strict serialized expression is deterministic).
"""

from __future__ import annotations

import base64
from typing import Any


class SfError(ValueError):
    """Malformed Structured Field value."""


class SfToken(str):
    """RFC 8941 Token type (not a quoted string; serialized without quotes)."""

    __slots__ = ()


# Allowed key/token characters (RFC 8941 key and token ABNF)
_KEY_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789*_-.")
_TCHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "!#$%&'*+-.^_`|~/"
)


def _fail(pos: int, msg: str) -> SfError:
    return SfError(f"position {pos}: {msg}")


def _skip_ows(value: str, pos: int) -> int:
    while pos < len(value) and value[pos] in " \t":
        pos += 1
    return pos


def _parse_key(value: str, pos: int) -> tuple[str, int]:
    if pos >= len(value) or value[pos] not in "abcdefghijklmnopqrstuvwxyz*":
        raise _fail(pos, "key must start with lcalpha or '*'")
    start = pos
    while pos < len(value) and value[pos] in _KEY_CHARS:
        pos += 1
    return value[start:pos], pos


def _parse_token(value: str, pos: int) -> tuple[SfToken, int]:
    start = pos
    while pos < len(value) and value[pos] in _TCHARS:
        pos += 1
    if start == pos:
        raise _fail(pos, "empty token")
    return SfToken(value[start:pos]), pos


def _parse_string(value: str, pos: int) -> tuple[str, int]:
    if pos >= len(value) or value[pos] != '"':
        raise _fail(pos, "expected a quoted string")
    pos += 1
    out: list[str] = []
    while pos < len(value):
        ch = value[pos]
        if ch == "\\":
            if pos + 1 >= len(value) or value[pos + 1] not in '"\\':
                raise _fail(pos, "only DQUOTE and backslash may be escaped")
            out.append(value[pos + 1])
            pos += 2
            continue
        if ch == '"':
            return "".join(out), pos + 1
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise _fail(pos, "control character inside a string")
        out.append(ch)
        pos += 1
    raise _fail(pos, "unterminated string")


def _parse_bytes(value: str, pos: int) -> tuple[bytes, int]:
    if pos >= len(value) or value[pos] != ":":
        raise _fail(pos, "expected a Byte Sequence")
    end = value.find(":", pos + 1)
    if end == -1:
        raise _fail(pos, "unterminated Byte Sequence")
    token = value[pos + 1 : end]
    try:
        decoded = base64.b64decode(token, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise SfError(f"invalid base64 inside a Byte Sequence: {exc}") from exc
    return decoded, end + 1


def _parse_bool(value: str, pos: int) -> tuple[bool, int]:
    if value[pos : pos + 2] not in ("?0", "?1"):
        raise _fail(pos, "invalid boolean")
    return value[pos + 1] == "1", pos + 2


def _parse_bare_item(value: str, pos: int) -> tuple[Any, int]:
    if pos >= len(value):
        raise _fail(pos, "expected an item")
    ch = value[pos]
    if ch == '"':
        return _parse_string(value, pos)
    if ch == ":":
        return _parse_bytes(value, pos)
    if ch == "?":
        return _parse_bool(value, pos)
    if ch == "*" or ch.isalpha():
        return _parse_token(value, pos)
    if ch.isdigit() or ch in "+-":
        return _parse_number(value, pos)
    raise _fail(pos, f"unknown item type: {ch!r}")


def _parse_number(value: str, pos: int) -> tuple[Any, int]:
    start = pos
    if value[pos] in "+-":
        pos += 1
    seen_dot = False
    frac = 0
    total = 0
    while pos < len(value) and (
        value[pos].isdigit() or (value[pos] == "." and not seen_dot)
    ):
        if value[pos] == ".":
            seen_dot = True
        else:
            total += 1
            if seen_dot:
                frac += 1
        pos += 1
    text = value[start:pos]
    if pos < len(value) and value[pos] == ".":
        raise _fail(pos, "two dots in a number")
    if seen_dot:
        if total == 0 or frac == 0 or total + frac > 16:
            raise _fail(start, "invalid decimal")
        return float(text), pos
    if total == 0 or total > 15:
        raise _fail(start, "invalid integer")
    return int(text), pos


def _parse_params(value: str, pos: int) -> tuple[dict[str, Any], int]:
    params: dict[str, Any] = {}
    while pos < len(value) and value[pos] == ";":
        pos += 1
        key, pos = _parse_key(value, pos)
        if pos < len(value) and value[pos] == "=":
            pos += 1
            item, pos = _parse_bare_item(value, pos)
            params[key] = item
        else:
            params[key] = True  # parameter without a value = boolean true
    return params, pos


def _parse_item_or_inner_list(value: str, pos: int) -> tuple[Any, dict[str, Any], int]:
    if pos < len(value) and value[pos] == "(":
        pos += 1
        items: list[tuple[Any, dict[str, Any]]] = []
        while True:
            pos = _skip_ows(value, pos)
            if pos < len(value) and value[pos] == ")":
                pos += 1
                break
            if pos >= len(value):
                raise _fail(pos, "unterminated inner list")
            bare, pos = _parse_bare_item(value, pos)
            params, pos = _parse_params(value, pos)
            items.append((bare, params))
        outer_params, pos = _parse_params(value, pos)
        return items, outer_params, pos
    bare, pos = _parse_bare_item(value, pos)
    params, pos = _parse_params(value, pos)
    return bare, params, pos


def sf_parse_dictionary(value: str) -> dict[str, tuple[Any, dict[str, Any]]]:
    """RFC 8941 Dictionary: {'sig1': (inner_items, params), ...}."""
    result: dict[str, tuple[Any, dict[str, Any]]] = {}
    pos = _skip_ows(value, 0)
    while True:
        if pos >= len(value):
            break
        key, pos = _parse_key(value, pos)
        pos = _skip_ows(value, pos)
        if pos < len(value) and value[pos] == "=":
            pos += 1
            member, params, pos = _parse_item_or_inner_list(value, pos)
            result[key] = (member, params)
        elif pos < len(value) and value[pos] == "(":
            member, params, pos = _parse_item_or_inner_list(value, pos)
            result[key] = (member, params)
        else:
            params, pos = _parse_params(value, pos)
            result[key] = (True, params)
        pos = _skip_ows(value, pos)
        if pos >= len(value):
            break
        if value[pos] != ",":
            raise _fail(pos, f"expected ',', got {value[pos]!r}")
        pos += 1
        pos = _skip_ows(value, pos)
        if pos >= len(value):
            raise _fail(pos, "trailing comma in dictionary")
    return result


def sf_parse_item(value: str) -> tuple[Any, dict[str, Any]]:
    """RFC 8941 Item (used for the legacy Signature-Agent form)."""
    pos = _skip_ows(value, 0)
    bare, params, pos = _parse_item_or_inner_list(value, pos)
    pos = _skip_ows(value, pos)
    if pos != len(value):
        raise _fail(pos, "trailing data after item")
    if isinstance(bare, list):
        raise SfError("expected an item, got an inner list")
    return bare, params


# --------------------------------------------------------------------------- #
#                                serialization                                  #
# --------------------------------------------------------------------------- #


def sf_serialize_bare_item(value: Any) -> str:
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, SfToken):
        return str(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    raise SfError(f"unsupported type: {type(value).__name__}")


def sf_serialize_params(params: dict[str, Any]) -> str:
    out = []
    for key, val in params.items():
        if val is True:
            out.append(f";{key}")
        else:
            out.append(f";{key}={sf_serialize_bare_item(val)}")
    return "".join(out)


def sf_serialize_item(value: Any, params: dict[str, Any]) -> str:
    return sf_serialize_bare_item(value) + sf_serialize_params(params)


def sf_serialize_inner_list(
    items: list[tuple[Any, dict[str, Any]]], params: dict[str, Any]
) -> str:
    inner = " ".join(sf_serialize_item(v, p) for v, p in items)
    return f"({inner})" + sf_serialize_params(params)
