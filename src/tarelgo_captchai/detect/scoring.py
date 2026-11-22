"""Scoring for TarelGo CaptchAI (spec section 4).

score = sum of the weights of FIRED CATEGORIES (not signals).
Decision B: score >= threshold AND >= 2 independent categories.
(Web Bot Auth never goes through scoring at all - it is a hard allow.)

The default threshold of 3 means: one strong category (TLS=3) plus anything
else, or two medium ones (UA=2 + fingerprint=2, fingerprint=2 + behavior=1,
and so on). A single weak signal never opens branch B.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .signals import CATEGORY_WEIGHTS, Signal


@dataclass(slots=True)
class Score:
    score: int
    categories: set[str]
    signals: list[str] = field(default_factory=list)
    reasons: dict[str, str] = field(default_factory=dict)


def score_signals(signals: list[Signal]) -> Score:
    categories: set[str] = set()
    named: list[str] = []
    reasons: dict[str, str] = {}
    for signal in signals:
        categories.add(signal.category)
        named.append(signal.name)
        reasons[signal.name] = signal.reason
    score = sum(CATEGORY_WEIGHTS[c] for c in categories)
    return Score(score=score, categories=categories, signals=named, reasons=reasons)


def should_route_b(score: Score, threshold: int) -> bool:
    """>= threshold points AND >= 2 independent categories (spec section 4)."""
    return score.score >= threshold and len(score.categories) >= 2
