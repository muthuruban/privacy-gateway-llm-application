# Evaluation guide

How to evaluate the gateway for the dissertation. The reproducible
harnesses live in [`evaluation/`](../evaluation/README.md); this
document explains what each metric means and how to interpret it.
Generated result files carry their own environment metadata (timestamp,
git commit, Python version, platform, dependency versions, test
configuration) — report those alongside any numbers, and do not present
one machine's results as universal.

## 1. Detection quality

Run `evaluation/run_detection_evaluation.py` against
`evaluation/datasets/synthetic_pii_cases.json` (or an extended corpus).

Definitions, per entity type and overall:

* **True positive (TP)** — a labelled entity span matched by a
  detection of the same type.
* **False positive (FP)** — a detection that matches no labelled span
  of that type.
* **False negative (FN)** — a labelled span with no matching detection.
* **Precision** = TP / (TP + FP): of what the detector flagged, how
  much was right. Low precision → over-redaction, damaged utility.
* **Recall** = TP / (TP + FN): of what was there, how much was found.
  Low recall → PII leaks. For a privacy gateway, recall on
  high-sensitivity types is the headline number.
* **F1** = harmonic mean of precision and recall.

Report per-entity results — an aggregate hides that, e.g., emails
(regex-based, near-perfect) and person names (NER-based, weaker) behave
completely differently. Vary `GATEWAY_SCORE_THRESHOLD` to trace the
precision/recall trade-off.

## 2. Leakage evaluation

Run `evaluation/run_leakage_evaluation.py`. It pushes fixture cases
through the full gateway and then searches for the known synthetic
values in:

1. the provider-boundary requests (captured by the mock adapter),
2. the audit database (raw file scan, not just parsed fields),
3. the application output/error responses,
4. captured application logs.

Every hit is reported and categorised by root cause: an
`allowed_crossing` (policy said allow), a `detector_false_negative`
(the value was never detected, so no policy could act — the documented
statistical limitation; these correlate with the recall numbers from
the detection evaluation), or a `mediation_failure` (the value was
detected and still leaked, or appeared in the audit store or logs —
a pipeline bug that must be zero). Report all three counts; only
mediation failures are acceptable to treat as regressions to fix, and
none may be silently dropped from the write-up.

## 3. Latency

Run `evaluation/run_latency_benchmark.py`. It compares four
configurations to isolate each cost:

1. mock provider call only (baseline),
2. detection only,
3. detection + tokenization,
4. full gateway including the audit write.

Reported statistics: count, warm-up count, median, mean, p95, min, max,
standard deviation. Use the **median** for the headline (NLP warm-up
and GC make means noisy) and p95 for tail behaviour. Note that the mock
provider removes network time — real deployments add provider latency
that typically dwarfs mediation cost; say so explicitly when
interpreting results.

## 4. Utility

To assess how mediation affects answer quality, send matched prompt
sets (original / redacted / tokenized) to a real model and rate the
responses for task success — e.g. exact-answer scoring for factual
tasks or blinded human rating for generative ones. This requires live
provider access and is deliberately not automated here; document your
rubric, sample sizes, and model version. Hypothesis worth testing:
tokenized prompts (stable referents) degrade utility less than blanket
redaction.

## 5. Audit tampering scenarios

Run `evaluation/run_audit_attack_evaluation.py`. It replays every
attack class from the threat model against a scratch database and
reports, per scenario: expected detectability (per the design docs),
observed verifier output, and whether they agree. Detected classes
should show `invalid` at the right record; the honestly-undetectable
classes (tail deletion, complete deletion, rollback without
checkpoint) should show `valid`/`empty` internally and `invalid` only
with the checkpoint — matching, not exceeding, the documented claims.
