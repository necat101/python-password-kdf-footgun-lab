# python-password-kdf-footgun-lab

A tiny, reproducible, local correctness and safety lab about Python stdlib password-hashing and KDF behavior, crypto API footguns, salt and verifier formatting, digest comparison policy, and safe scope boundaries. Inspired by the Hacker News discussion on "Okta Bcrypt incident lessons for designing better APIs".

**Repo:** https://github.com/necat101/python-password-kdf-footgun-lab

## Hacker News thread access

The HN thread at https://news.ycombinator.com/item?id=42955176 was accessed via the Hacker News Firebase API CLI **before** writing this README. The sentiment summary below reflects the actual HN discussion, not just the linked article title.

Evidence artifact: `hn_thread_evidence.md` (includes raw API dump at `hn_42955176.json`).

The thread had 166 comments – sentiment summary below is based on ~26 top-level comments fetched via the HN API.

## What Hacker News users were actually debating

**bcrypt's 72-byte input limit and silent truncation versus explicit errors.** The Okta incident centered on bcrypt silently truncating inputs beyond 72 bytes. Multiple commenters argued forcefully: "libraries should reject input they can't correctly handle instead of silently truncating it" and "The default API must be the strict one. You should be able to configure it to be broken but silent truncation is an insane piece of functionality." Others noted that some bcrypt implementations do document the truncation, citing the Zig stdlib which provides both `bcrypt()` (truncation documented) and `bcryptWithoutTruncation()` (recommended, pre-hashes long passwords).

**Password hashes versus KDFs.** A top comment: "Bcrypt is a password hash, not a KDF, which is the way it was used in this API. … A KDF is a generally-useful bit of cryptography joinery; a password hash has exactly one job." This sparked discussion about whether password hashes and KDFs overlap or are distinct – some argued the distinction matters for API design, others saw them as closely related. One commenter asked plainly: "Can someone explain, in clear layman terms, what the difference is between a password hash and a KDF?"

**Salts, cost factors, slow hashing, HMAC, PBKDF2, scrypt, Argon2.** Commenters discussed the usual password-hashing stack: salts must be unique, cost factors must be tunable, hashing must be slow. PBKDF2, scrypt, bcrypt, and Argon2 all came up. "Has Argon2 basically overtaken Bcrypt in recent years?" was asked. One commenter noted: "Don't conceive your own cryptographic hacks. Use existing KDF designed by professionals."

**Password material inside cache keys is suspicious.** The Okta incident involved `bcrypt(userId + username + password)` being used to generate a cache key. Commenters flagged multiple issues: "password is kept around somewhere, which is not the best practice", cache key collisions should be caught by verifying the cached value matches the data used in the hash, and "crypto primitives should not be composed casually". One commenter: "password material in cache keys … is a design smell."

**API design footguns and dangerous defaults.** "Documentation is not enough if dangerous defaults are easy to misuse" was a recurring theme. Silent truncation, missing input validation, confusing password-hash-vs-KDF APIs, and cache-key composition without verification all came up. Interoperability can conflict with safer defaults – changing bcrypt's 72-byte behavior would break existing verifiers, but keeping it silent risks new bugs.

**"Just use bcrypt" is not enough context.** Multiple commenters pushed back on simplistic "just use bcrypt" advice, pointing out that bcrypt's input limit, the need for proper salt handling, cost factor selection, and the difference between password hashing and general-purpose KDFs all require understanding. Fast hashes like SHA-512 were correctly called out as wrong for password storage: "Is there a reason I might be missing [why not SHA-512]?" – password hashing needs slow/expensive, not fast.

**Language-specific implementation differences.** Ruby bcrypt doesn't error on >72 byte input. Zig provides both truncating and non-truncating variants. Node's built-in crypto module doesn't ship bcrypt (OpenSSL doesn't support it). PHP frameworks commonly use bcrypt. These cross-language differences were noted but no one claimed any single implementation was universally correct.

**Python's hashlib/hmac/secrets are useful but not a universal password-storage proof.** No HN commenter claimed Python's stdlib alone proves production authentication security. The discussion was about crypto API design broadly, not Python specifically.

## What this lab actually tests

50 deterministic synthetic password/KDF cases covering:

- unsalted SHA256 fast-hash footgun, repeated fast hash collision
- PBKDF2 with unique salts, different passwords, verifier metadata (algorithm, iterations, salt, digest length)
- PBKDF2 verify success / wrong password fail, iteration count changes output, low iteration caveat, SHA256 vs SHA512 metadata
- salt generation with `secrets.token_bytes`, fixed salt negative case, short salt caveat, salt uniqueness
- scrypt availability check / optional skip, scrypt n/r/p parameter metadata, memory cost caveat
- `hmac.compare_digest` success/failure, plain equality comparison caveat
- hex vs binary digest, base64 verifier encoding
- malformed verifier parse error, missing algorithm/cost/salt metadata negative cases
- Unicode UTF-8 secret encoding, bytes vs str boundary, normalization NOT silently applied, NUL byte caveat
- long input length policy, bcrypt 72-byte truncation NOT_TESTED marker
- Argon2 NOT in stdlib marker, bcrypt NOT in stdlib marker
- pepper NOT_TESTED marker, password in cache key smell marker
- HMAC domain separation toy case, HMAC key vs salt distinction
- `secrets` vs `random` caveat, deterministic test salt mode
- timing microbenchmark NOT proof marker
- password strength / breach resistance / rate limiting / database storage / production auth NOT_TESTED markers
- naive unsalted fast hash footgun cases

16 methods, all Python stdlib only (`hashlib`, `hmac`, `secrets`, `base64`, etc.):

1. `preserve_original_secret_text_baseline`
2. `sha256_fast_hash_footgun_observer`
3. `pbkdf2_hmac_verifier_checker`
4. `scrypt_verifier_checker`
5. `salt_generation_policy_checker`
6. `fixed_salt_negative_detector`
7. `verifier_format_parser_checker`
8. `hmac_compare_digest_checker`
9. `plain_equality_compare_caveat_marker`
10. `encoding_boundary_checker`
11. `input_length_policy_checker`
12. `hmac_domain_separation_demo`
13. `password_hash_vs_kdf_scope_checker`
14. `cache_key_password_material_not_tested_marker`
15. `naive_unsalted_fast_hash_marker`
16. `external_password_storage_not_tested_marker`

## Results

```
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
naive_unsalted_fast_hash_marker: 41/50 correct  ← expected failures
external_password_storage_not_tested_marker: 50/50 correct
```

The naive unsalted fast hash marker fails 9/50 cases – unsalted SHA256, repeated fast hash, fixed salt, equality comparison, malformed verifier, missing metadata, password cache key smell – exactly as expected.

## Scope and safety

This is a **toy local lab**, NOT a production authentication system, password manager, login server, credential stuffing tool, password cracker, compliance tool, Redis or cache-key reproducer, Okta incident reproduction, or cryptographic advice.

- Synthetic data only: `example_user`, `demo_account`, `synthetic_password_case`, `toy_secret`, `fake_login_row`, `sample_verifier`, `fictional_admin`, `test_service`, `demo_kdf_record`
- No real passwords, customer records, usernames, email addresses, breach corpora, common-password lists, leaked hashes, logs, or telemetry
- No external crypto/password libraries: no bcrypt, passlib, argon2-cffi, cryptography, pynacl, libsodium, pyopenssl
- No password cracking: no hashcat, John the Ripper, wordlists, rockyou, haveibeenpwned API
- No infrastructure: no OAuth, web app, database server, Redis, LDAP
- No network: no requests, curl, web APIs, downloading password lists
- No external runtimes: no jq, node, Rust, Go
- Python stdlib only

**Do not claim this lab proves a real password storage scheme is secure, compliant, breach-resistant, production-ready, user-safe, or cryptographically reviewed.**

The lab distinguishes carefully between:
- what HN commenters discussed
- what the linked Okta/bcrypt article claims
- what bcrypt/Argon2 libraries outside the stdlib do
- what Python's `hashlib`/`hmac`/`secrets` modules expose
- what OWASP/NIST password-storage guidance says
- what this toy lab can actually prove

Fast hashes are the wrong mental model for low-entropy passwords; salts must be unique and stored with the verifier; password hashes and KDFs overlap but are not interchangeable in every API context; input encoding and length policies matter; dangerous defaults should be documented or rejected; comparison should use `compare_digest`; algorithm, salt, cost, and digest metadata need to travel together.

## Running the lab

```bash
python3 -m py_compile generate_cases.py run_lab.py
python3 generate_cases.py
python3 run_lab.py
```

Outputs:
- `RESULTS.md` – summary tables
- `results_rows.json` / `results_rows.csv` – per-case/per-method artifact
- `VERIFY.md` – fresh-clone verification transcript

Python 3.12+, stdlib only, zero external dependencies, zero network calls, zero subprocesses.

`hashlib.scrypt` availability depends on OpenSSL support – the lab records a clear optional-feature skip if unavailable.

## References

- HN thread: https://news.ycombinator.com/item?id=42955176
- Article: https://n0rdy.foo/posts/20250121/okta-bcrypt-lessons-for-better-apis/
- Python hashlib docs: https://docs.python.org/3/library/hashlib.html
- Python hmac docs: https://docs.python.org/3/library/hmac.html
- Python secrets docs: https://docs.python.org/3/library/secrets.html
- OWASP password storage cheat sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- NIST SP 800-63B: https://pages.nist.gov/800-63-4/sp800-63b/authenticators/
