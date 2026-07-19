# Evaluation utilities

Reproducible harnesses for the dissertation's evaluation chapter. See
[docs/EVALUATION_GUIDE.md](../docs/EVALUATION_GUIDE.md) for what each
metric means and how to interpret results.

All input data is synthetic (`datasets/synthetic_pii_cases.json`); no
harness makes live provider calls. Run everything from the repository
root with the virtual environment active:

```bash
python -m evaluation.run_detection_evaluation    # precision / recall / F1 per entity
python -m evaluation.run_leakage_evaluation      # fixture-value search across all boundaries
python -m evaluation.run_latency_benchmark 50    # 4-stage latency comparison (50 iterations)
python -m evaluation.run_audit_attack_evaluation # tamper scenarios vs documented claims
```

Each run writes a timestamped JSON file to `evaluation/results/`
containing the numbers **plus provenance**: UTC timestamp, git commit,
Python version, platform, dependency versions, and the test
configuration. `evaluation/results/` is gitignored — generated numbers
are environment-specific snapshots, not universal claims; quote them in
the dissertation together with their provenance block.

Exit codes: the leakage and audit-attack harnesses exit non-zero when
observations diverge from the documented expectations, so they can act
as extended regression checks.
