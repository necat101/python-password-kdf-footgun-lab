# VERIFY.md — Fresh-clone verification

```console
$ git clone https://github.com/necat101/python-password-kdf-footgun-lab.git verify_clone
Cloning into 'verify_clone'...
$ cd verify_clone
$ python3 -m py_compile generate_cases.py run_lab.py
$ python3 generate_cases.py
Wrote 50 cases to cases.json
$ python3 run_lab.py
Total rows: 800, correct: 791, failed: 9
preserve_original_secret_text_baseline: 50/50 correct
sha256_fast_hash_footgun_observer: 50/50 correct
pbkdf2_hmac_verifier_checker: 50/50 correct
scrypt_verifier_checker: 50/50 correct
salt_generation_policy_checker: 50/50 correct
fixed_salt_negative_detector: 50/50 correct
verifier_format_parser_checker: 50/50 correct
hmac_compare_digest_checker: 50/50 correct
plain_equality_compare_caveat_marker: 50/50 correct
encoding_boundary_checker: 50/50 correct
input_length_policy_checker: 50/50 correct
hmac_domain_separation_demo: 50/50 correct
password_hash_vs_kdf_scope_checker: 50/50 correct
cache_key_password_material_not_tested_marker: 50/50 correct
naive_unsalted_fast_hash_marker: 41/50 correct
external_password_storage_not_tested_marker: 50/50 correct
Wrote RESULTS.md, results_rows.json/csv
```

Environment:
- Python: 3.12.3
- Platform: Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
- hashlib/hmac/secrets: available (stdlib)
- hashlib.scrypt available: True
- Cases: 50
- Methods: 16
- Subprocesses: 0
- Random seed: 42
- HN thread accessed: yes – https://news.ycombinator.com/item?id=42955176
- Network/API calls during benchmark: none
- External crypto/password libraries: none
- Password cracking tools: none

The naive unsalted fast hash marker failing 9/50 cases is expected – unsalted SHA256, repeated fast hash, fixed salt, equality comparison, malformed verifier, missing metadata, password cache key smell all break naive assumptions.
```
