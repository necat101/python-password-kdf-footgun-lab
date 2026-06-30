# LAB_NOTES.md

## Development history – no case expectation gotchas (2026-06-30)

Unlike `python-json-minefield-lab` (4 case expectation mismatches: control_char, BOM, NaN×2)
and `python-csv-dialect-footgun-lab` (unescaped_quote expectation + AttributeError bug +
Sniffer scoring), this password/KDF lab had **no case expectation gotchas**.

All 15 stdlib methods scored 50/50 correct on the first full `run_lab.py` execution after
writing `generate_cases.py` and `run_lab.py`. The naive unsalted fast hash marker correctly
failed 9/50 cases (unsalted SHA256, repeated fast hash, fixed salt, equality comparison,
malformed verifier, missing algorithm/cost/salt metadata, password cache key smell) – these
failures were expected from the start and are documented in the case metadata
(`naive_should_fail: true`).

This is noted here explicitly so that the "no case expectation gotchas / first full run" claim
in commit messages and memory files is auditable in-repo, not just a local agent memory claim.
Compare with:
- `python-json-minefield-lab/LAB_NOTES.md` – documents 4 case expectation fixes (control_char, BOM, NaN×2)
- `python-csv-dialect-footgun-lab/LAB_NOTES.md` – documents unescaped_quote expectation fix, AttributeError bug (`case.get("parsing_obs", "").startswith(...)` → `(case.get("parsing_obs") or "").startswith(...)`), Sniffer scoring change
- `python-floating-point-footgun-lab/LAB_NOTES.md` – documents clean first run, no expectation repairs needed

For this password/KDF lab: no post-run expectation repairs were needed, and naive failures were
expected from the start.

## Results accounting

RESULTS.md explicitly breaks out:
- Stdlib methods (15 methods × 50 cases = 750 rows): correct: 750, failed: 0
- Naive unsalted fast hash marker (1 method × 50 cases = 50 rows): correct: 41, failed: 9 (expected)
- Unexpected failures: 0

This matches the accounting style from `python-json-minefield-lab`,
`python-csv-dialect-footgun-lab`, and `python-floating-point-footgun-lab` – naive failures are
expected evidence of the footgun, not real implementation bugs.

## hashlib.scrypt availability

`hashlib.scrypt` availability depends on OpenSSL support at Python build time. The
`scrypt_verifier_checker` method checks `hasattr(hashlib, "scrypt")` and records a clear
optional-feature skip if unavailable. On the development machine (Python 3.12.3,
OpenSSL-backed), `hashlib.scrypt` is available and the method scores 50/50 correct.

The results_rows.csv/json artifacts will reflect whether scrypt was available during the run –
check the `scrypt_verifier_checker` rows for `ok` / `correct` / `reason` fields.
