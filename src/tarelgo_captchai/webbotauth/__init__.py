"""Web Bot Auth for TarelGo CaptchAI: sfv (RFC 8941), base (RFC 9421),
keys (RFC 7638/8032), directory (agent keys + SSRF protection), verify."""

from .base import (
    SUPPORTED_DERIVED,
    RequestParts,
    build_signature_base,
    derive_component_value,
    field_values_map,
    normalize_authority,
)
from .directory import (
    DIRECTORY_PATH,
    AgentEntry,
    AgentKeyError,
    AgentKeyResolver,
    ResolvedKey,
)
from .keys import (
    InvalidKeyError,
    b64url_decode,
    jwk_public_key,
    jwk_thumbprint,
    select_jwk,
)
from .sfv import SfError, sf_parse_dictionary, sf_parse_item
from .verify import (
    WBA_TAG,
    VerifyInput,
    WbaError,
    WbaResult,
    verify_web_bot_auth,
)

__all__ = [
    "DIRECTORY_PATH",
    "SUPPORTED_DERIVED",
    "WBA_TAG",
    "AgentEntry",
    "AgentKeyError",
    "AgentKeyResolver",
    "InvalidKeyError",
    "RequestParts",
    "ResolvedKey",
    "SfError",
    "VerifyInput",
    "WbaError",
    "WbaResult",
    "b64url_decode",
    "build_signature_base",
    "derive_component_value",
    "field_values_map",
    "jwk_public_key",
    "jwk_thumbprint",
    "normalize_authority",
    "sf_parse_dictionary",
    "sf_parse_item",
    "select_jwk",
    "verify_web_bot_auth",
]
