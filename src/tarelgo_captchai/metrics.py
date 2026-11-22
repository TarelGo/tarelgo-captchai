"""Prometheus-format metrics for TarelGo CaptchAI (zero extra dependencies).

Metric names are branded at the key level: tarelgo_captchai_*.
The /metrics endpoint is for internal use only (spec section 7).
"""

from __future__ import annotations

import threading

LATENCY_BUCKETS_MS = (5, 10, 20, 30, 50, 100, 250, 500, 1000, 2000)

HISTOGRAM_BASE = "tarelgo_captchai_request_latency_ms"


class MetricsRegistry:
    """Minimal in-process registry: labeled counters + a latency histogram."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, float] = {}

    def inc(self, name: str, **labels: str) -> None:
        key = f"{name}{self._render_labels(labels)}"
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + 1.0

    def observe_latency_ms(self, path: str, latency_ms: float) -> None:
        labels = {"path": path}
        with self._lock:
            for bucket in LATENCY_BUCKETS_MS:
                if latency_ms <= bucket:
                    key = (
                        f"{HISTOGRAM_BASE}_bucket"
                        f"{self._render_labels({**labels, 'le': str(bucket)})}"
                    )
                    self._counters[key] = self._counters.get(key, 0.0) + 1.0
            key_inf = (
                f"{HISTOGRAM_BASE}_bucket{self._render_labels({**labels, 'le': '+Inf'})}"
            )
            self._counters[key_inf] = self._counters.get(key_inf, 0.0) + 1.0
            key_sum = f"{HISTOGRAM_BASE}_sum{self._render_labels(labels)}"
            self._counters[key_sum] = self._counters.get(key_sum, 0.0) + latency_ms
            key_cnt = f"{HISTOGRAM_BASE}_count{self._render_labels(labels)}"
            self._counters[key_cnt] = self._counters.get(key_cnt, 0.0) + 1.0

    @staticmethod
    def _render_labels(labels: dict[str, str]) -> str:
        if not labels:
            return ""
        inner = ",".join(f'{k}="{v}"' for k, v in labels.items())
        return "{" + inner + "}"

    def render(self) -> str:
        lines = [
            "# TarelGo CaptchAI metrics - TarelGo Development (https://tarelgo.com)",
            "# TYPE tarelgo_captchai_decisions_total counter",
        ]
        with self._lock:
            items = sorted(self._counters.items())
        histogram_types = {
            f"{HISTOGRAM_BASE}_bucket": "histogram",
            f"{HISTOGRAM_BASE}_sum": "histogram",
            f"{HISTOGRAM_BASE}_count": "histogram",
        }
        emitted_types: set[str] = set()
        for key, value in items:
            base = key.split("{")[0]
            if base.startswith(f"{HISTOGRAM_BASE}_bucket"):
                if base not in emitted_types:
                    lines.append(f"# TYPE {HISTOGRAM_BASE} histogram")
                    emitted_types.add(base)
                lines.append(f"{key} {value}")
                continue
            if base not in emitted_types:
                metric_type = histogram_types.get(base, "counter")
                lines.append(f"# TYPE {base} {metric_type}")
                emitted_types.add(base)
            lines.append(f"{key} {value}")
        return "\n".join(lines) + "\n"


metrics = MetricsRegistry()
