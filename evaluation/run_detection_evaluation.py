"""Detection-quality evaluation: precision, recall, and F1 per entity
type and overall, against the labelled synthetic dataset.

Matching rule: a labelled entity counts as detected (TP) when a
detection of the same type overlaps the labelled value's character span
in the text. Detections of a policy-listed type that overlap no
labelled span of that type count as false positives; unmatched labels
count as false negatives.

Usage:  python -m evaluation.run_detection_evaluation
"""

from __future__ import annotations

from typing import Any

from evaluation.common import environment_metadata, load_dataset, write_results
from gateway.pii_mediator import PIIMediator


def _spans_of(text: str, value: str) -> list[tuple[int, int]]:
    spans = []
    start = text.find(value)
    while start != -1:
        spans.append((start, start + len(value)))
        start = text.find(value, start + 1)
    return spans


def _overlaps(a: tuple[int, int], b: tuple[int, int]) -> bool:
    return a[0] < b[1] and b[0] < a[1]


def evaluate(mediator: PIIMediator, cases: list[dict[str, Any]]) -> dict[str, Any]:
    counters: dict[str, dict[str, int]] = {}

    def bump(entity_type: str, key: str) -> None:
        counters.setdefault(entity_type, {"tp": 0, "fp": 0, "fn": 0})[key] += 1

    per_case = []
    for case in cases:
        text = case["text"]
        detections = mediator.analyze(text)
        matched_detections: set[int] = set()
        case_fns = []

        for entity in case["entities"]:
            spans = _spans_of(text, entity["value"])
            hit = False
            for index, det in enumerate(detections):
                if det.entity_type == entity["type"] and any(
                    _overlaps((det.start, det.end), span) for span in spans
                ):
                    matched_detections.add(index)
                    hit = True
            if hit:
                bump(entity["type"], "tp")
            else:
                bump(entity["type"], "fn")
                case_fns.append(entity["type"])

        case_fps = []
        for index, det in enumerate(detections):
            if index not in matched_detections:
                bump(det.entity_type, "fp")
                case_fps.append(det.entity_type)

        per_case.append(
            {"id": case["id"], "false_negatives": case_fns, "false_positives": case_fps}
        )

    def scores(c: dict[str, int]) -> dict[str, Any]:
        tp, fp, fn = c["tp"], c["fp"], c["fn"]
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision and recall and (precision + recall)
            else (0.0 if precision is not None and recall is not None else None)
        )
        return {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1": round(f1, 4) if f1 is not None else None,
        }

    overall = {"tp": 0, "fp": 0, "fn": 0}
    for c in counters.values():
        for key in overall:
            overall[key] += c[key]

    return {
        "per_entity": {entity: scores(c) for entity, c in sorted(counters.items())},
        "overall": scores(overall),
        "per_case": per_case,
    }


def main() -> None:
    cases = load_dataset()
    mediator = PIIMediator()
    results = evaluate(mediator, cases)

    print(f"{'entity type':<16} {'TP':>4} {'FP':>4} {'FN':>4} {'prec':>7} {'recall':>7} {'F1':>7}")
    for entity, s in results["per_entity"].items():
        print(
            f"{entity:<16} {s['tp']:>4} {s['fp']:>4} {s['fn']:>4} "
            f"{s['precision'] if s['precision'] is not None else '-':>7} "
            f"{s['recall'] if s['recall'] is not None else '-':>7} "
            f"{s['f1'] if s['f1'] is not None else '-':>7}"
        )
    o = results["overall"]
    print(
        f"{'OVERALL':<16} {o['tp']:>4} {o['fp']:>4} {o['fn']:>4} "
        f"{o['precision']:>7} {o['recall']:>7} {o['f1']:>7}"
    )

    payload = {
        "evaluation": "detection",
        "dataset": "synthetic_pii_cases.json",
        "cases": len(cases),
        "results": results,
        "environment": environment_metadata(
            {"score_threshold": mediator.score_threshold, "spacy_model": "en_core_web_sm"}
        ),
    }
    path = write_results("detection", payload)
    print(f"\nResults written to {path}")


if __name__ == "__main__":
    main()
