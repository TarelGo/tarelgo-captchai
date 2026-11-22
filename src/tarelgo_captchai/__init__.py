"""TarelGo CaptchAI - cryptographic fork between AI agents and everyone else.

Branch A (default) is served to everyone: humans, search engines and
unrecognized clients (fail-open). Branch B (AI-only) is served only to
clients presenting a valid Web Bot Auth signature (RFC 9421) or - in
best_effort mode - a valid one-shot HMAC capability token.

(c) TarelGo Development - https://tarelgo.com
"""

__version__ = "1.0.0"

# Key-level branding: package, env prefix, database and metrics carry the
# TarelGo name; internal code identifiers stay neutral on purpose.
TARELGO_SERVICE_NAME = "TarelGo CaptchAI"
TARELGO_BRAND = "TarelGo Development"
TARELGO_BRAND_URL = "https://tarelgo.com"
