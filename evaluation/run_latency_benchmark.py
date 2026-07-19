"""Latency benchmark comparing four configurations to isolate the cost
of each pipeline stage:

1. mock provider call only (baseline, no gateway),
2. PII detection only,
3. detection + tokenization,
4. full gateway request including the audit write.

The mock provider removes network time: real deployments add provider
latency on top of every configuration. Use the median as the headline
figure and p95 for tail behaviour.

Usage:  python -m evaluation.run_latency_benchmark [iterations]
"""

from __future__ import annotations

import asyncio
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from evaluation.common import environment_metadata, write_results
from gateway.config import Settings
from gateway.gateway_api import create_app
from gateway.llm_client import MockLLMClient
from gateway.pii_mediator import PIIMediator
from gateway.tokenization import TokenizationContext

PROMPT = (
    "Hi, I'm John Smith. Email me at john.smith@example.com or call "
    "+44 7700 900123 about the December delivery to Manchester."
)
WARMUP = 5


def _stats(samples_ms: list[float]) -> dict[str, Any]:
    ordered = sorted(samples_ms)
    p95_index = min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))
    return {
        "count": len(samples_ms),
        "warmup_discarded": WARMUP,
        "median_ms": round(statistics.median(ordered), 2),
        "mean_ms": round(statistics.fmean(ordered), 2),
        "p95_ms": round(ordered[p95_index], 2),
        "min_ms": round(ordered[0], 2),
        "max_ms": round(ordered[-1], 2),
        "stdev_ms": round(statistics.pstdev(ordered), 2) if len(ordered) > 1 else 0.0,
    }


def _bench(fn, iterations: int) -> dict[str, Any]:
    for _ in range(WARMUP):
        fn()
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return _stats(samples)


def main() -> None:
    iterations = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    mediator = PIIMediator()
    mock = MockLLMClient()

    settings = Settings.load(
        _env_file=None,
        app_env="test",
        provider="mock",
        audit_db_path=str(Path(tempfile.mkdtemp(prefix="gateway-bench-")) / "audit.db"),
        audit_hmac_key="latency-benchmark-hmac-key-000001",
    )
    app = create_app(settings=settings, mediator=mediator, llm_client=MockLLMClient())
    client = TestClient(app)
    request_body = {
        "model": "bench",
        "messages": [{"role": "user", "content": PROMPT}],
    }

    def provider_only() -> None:
        asyncio.run(mock.chat("bench", [{"role": "user", "content": PROMPT}]))

    def detection_only() -> None:
        mediator.analyze(PROMPT)

    def detection_and_tokenization() -> None:
        context = TokenizationContext(PROMPT)
        mediator.apply(PROMPT, mediator.analyze(PROMPT), context)

    def full_gateway() -> None:
        response = client.post("/v1/chat/completions", json=request_body)
        response.raise_for_status()

    configurations = {
        "1_mock_provider_only": provider_only,
        "2_detection_only": detection_only,
        "3_detection_and_tokenization": detection_and_tokenization,
        "4_full_gateway_with_audit": full_gateway,
    }

    results = {}
    for name, fn in configurations.items():
        results[name] = _bench(fn, iterations)
        s = results[name]
        print(
            f"{name:<30} median={s['median_ms']:>8}ms mean={s['mean_ms']:>8}ms "
            f"p95={s['p95_ms']:>8}ms (n={s['count']})"
        )

    payload = {
        "evaluation": "latency",
        "prompt_chars": len(PROMPT),
        "results": results,
        "environment": environment_metadata(
            {"iterations": iterations, "warmup": WARMUP, "provider": "mock (no network)"}
        ),
    }
    path = write_results("latency", payload)
    print(f"\nResults written to {path}")


if __name__ == "__main__":
    main()
