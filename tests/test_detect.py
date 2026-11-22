"""Detection and scoring tests for TarelGo CaptchAI (spec section 13 No.1-5)."""

from __future__ import annotations

from tarelgo_captchai.detect import (
    DEFAULT_UA_AI_LIST,
    accept_html_signal,
    accept_language_signal,
    browser_claim,
    header_order_signal,
    ja3_scoring_signal,
    missing_client_hints_signal,
    no_sec_fetch_signal,
    score_signals,
    should_route_b,
    ua_ai_signal,
)

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/126.0.0.0 Safari/537.36"
)


def browser_headers() -> dict[str, str]:
    return {
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "sec-ch-ua": '"Chromium";v="126"',
        "accept": "text/html,application/xhtml+xml",
        "accept-language": "en-US,en;q=0.9",
    }


def test_no1_real_browser_gets_no_signals() -> None:
    """A real browser sends Sec-Fetch-*, client hints and Accept-Language."""
    signals = [
        ua_ai_signal(BROWSER_UA, list(DEFAULT_UA_AI_LIST)),
        no_sec_fetch_signal(BROWSER_UA, browser_headers()),
        missing_client_hints_signal(BROWSER_UA, browser_headers()),
        header_order_signal(BROWSER_UA, 15),
        accept_language_signal(BROWSER_UA, browser_headers()),
        accept_html_signal(BROWSER_UA, browser_headers()),
    ]
    signals = [s for s in signals if s is not None]
    score = score_signals(signals)
    assert score.score == 0
    assert not should_route_b(score, threshold=3)


def test_no2_curl_with_declared_bot_stays_below_threshold() -> None:
    """curl + GPTBot: only the UA declaration fires (weight 2 < 3)."""
    signals = [
        ua_ai_signal("curl/8.5.0 GPTBot/1.0", list(DEFAULT_UA_AI_LIST)),
        # curl does not claim to be a browser -> fingerprint signals are gated off
        no_sec_fetch_signal("curl/8.5.0 GPTBot/1.0", {}),
        accept_language_signal("curl/8.5.0 GPTBot/1.0", {}),
    ]
    signals = [s for s in signals if s is not None]
    assert [s.name for s in signals] == ["ua_ai"]
    score = score_signals(signals)
    assert score.score == 2
    assert not should_route_b(score, threshold=3)


def test_no3_browser_impostor_crosses_the_threshold() -> None:
    """Browser-claimed UA without Sec-Fetch / Accept-Language: fingerprint + behavior."""
    impostor = "Mozilla/5.0 (compatible; MyCrawler/1.0)"
    signals = [
        s
        for s in (
            ua_ai_signal(impostor, list(DEFAULT_UA_AI_LIST)),
            no_sec_fetch_signal(impostor, {}),
            accept_language_signal(impostor, {}),
        )
        if s is not None
    ]
    names = {s.name for s in signals}
    assert "no_sec_fetch" in names
    assert "accept_language_unrealistic" in names
    score = score_signals(signals)
    assert score.score >= 3
    assert len(score.categories) >= 2
    assert should_route_b(score, threshold=3)


def test_no4_chrome_ua_without_client_hints_is_caught() -> None:
    """Chrome-claimed UA must carry sec-ch-ua."""
    chrome_ua = "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0"
    assert missing_client_hints_signal(chrome_ua, {}) is not None
    assert missing_client_hints_signal(chrome_ua, {"sec-ch-ua": '"Chromium"'}) is None


def test_browser_gate_blocks_signals_for_non_browser_ua() -> None:
    """Without a browser claim the fingerprint/behavior signals never fire."""
    plain = "python-httpx/0.28"
    assert no_sec_fetch_signal(plain, {}) is None
    assert accept_language_signal(plain, {}) is None
    assert accept_html_signal(plain, {}) is None
    assert header_order_signal(plain, 2) is None


def test_thin_header_set_is_suspicious_only_for_browser_ua() -> None:
    assert header_order_signal(BROWSER_UA, 5) is not None
    assert header_order_signal(BROWSER_UA, 6) is None


def test_ja3_known_hash_gives_tls_category() -> None:
    signal = ja3_scoring_signal("aabbccdd00112233", {"aabbccdd00112233"})
    assert signal is not None
    assert signal.category == "tls"
    assert signal.weight == 3
    assert ja3_scoring_signal("deadbeef", {"aabbccdd00112233"}) is None
    assert ja3_scoring_signal(None, {"aabbccdd00112233"}) is None


def test_score_needs_two_categories() -> None:
    """Two signals in ONE category must not open branch B."""
    from tarelgo_captchai.detect import Signal

    same_category = [
        Signal("a", "fingerprint", 2, "x"),
        Signal("b", "fingerprint", 2, "y"),
    ]
    score = score_signals(same_category)
    # Category weights are counted once per category, not per signal.
    assert score.score == 2
    assert not should_route_b(score, threshold=3)


def test_browser_claim_detection() -> None:
    assert browser_claim(BROWSER_UA)
    assert browser_claim("Mozilla/5.0 (compatible)")
    assert not browser_claim("curl/8.5.0")
    assert not browser_claim("")
