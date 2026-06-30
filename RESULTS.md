# python-password-kdf-footgun-lab — Results

Total rows: 800, correct: 791, failed: 9

Breakdown:
- Stdlib methods (15 methods × 50 cases = 750 rows): correct: 750, failed: 0
- Naive unsalted fast hash marker (1 method × 50 cases = 50 rows): correct: 41, failed: 9 (expected – naive unsalted fast hash fails on salt/verifier/metadata/comparison footgun cases)
- **Unexpected failures: 0**

## Per-method

| Method | Correct | Total | Note |
|---|---|---|---|
| preserve_original_secret_text_baseline | 50 | 50 |  |
| sha256_fast_hash_footgun_observer | 50 | 50 |  |
| pbkdf2_hmac_verifier_checker | 50 | 50 |  |
| scrypt_verifier_checker | 50 | 50 |  |
| salt_generation_policy_checker | 50 | 50 |  |
| fixed_salt_negative_detector | 50 | 50 |  |
| verifier_format_parser_checker | 50 | 50 |  |
| hmac_compare_digest_checker | 50 | 50 |  |
| plain_equality_compare_caveat_marker | 50 | 50 |  |
| encoding_boundary_checker | 50 | 50 |  |
| input_length_policy_checker | 50 | 50 |  |
| hmac_domain_separation_demo | 50 | 50 |  |
| password_hash_vs_kdf_scope_checker | 50 | 50 |  |
| cache_key_password_material_not_tested_marker | 50 | 50 |  |
| naive_unsalted_fast_hash_marker | 41 | 50 | expected naive failures |
| external_password_storage_not_tested_marker | 50 | 50 |  |

## Environment

- Python: 3.12.3
- hashlib/hmac/secrets: available
- hashlib.scrypt available: True
- Platform: Linux-6.17.0-1009-aws-x86_64-with-glibc2.39
- Cases: 50
- Methods: 16
- Subprocesses: 0
- Random seed: 42
- HN thread accessed: yes – https://news.ycombinator.com/item?id=42955176
- Network/API calls during benchmark: none
- External crypto/password libraries: none
- Password cracking tools: none
