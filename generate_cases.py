#!/usr/bin/env python3
"""Generate deterministic password/KDF footgun cases."""
import json, hashlib, hmac, secrets, base64

CASES = []
def add(case_id, category, fake_record, context, **kw):
    CASES.append({"case_id": case_id, "category": category, "fake_record": fake_record, "context": context, **kw})

# fast hash footgun
add("c01_unsalted_sha256", "fast_hash_footgun", "example_user", "fast_hash_footgun",
    secret_label="toy_secret_1", secret_bytes_len=12, salt_bytes_len=0,
    algorithm="sha256", cost_param=None, expected_success=False,
    expected_digest_obs="unsalted_fast_hash_footgun", naive_should_fail=True)
add("c02_repeated_fast_hash", "fast_hash_footgun", "demo_account", "fast_hash_footgun",
    secret_label="toy_secret_1", secret_bytes_len=12, salt_bytes_len=0,
    algorithm="sha256", expected_digest_obs="same_input_same_output", naive_should_fail=True)
# PBKDF2 salt uniqueness
add("c03_pbkdf2_unique_salt", "salt_policy", "synthetic_password_case", "salt_policy",
    secret_label="toy_secret_1", secret_bytes_len=12, salt_bytes_len=16,
    algorithm="pbkdf2_hmac", hash_name="sha256", cost_param=100000,
    expected_digest_obs="unique_salt_different_output", expected_salt_obs="salt_unique")
add("c04_pbkdf2_same_salt_diff_password", "salt_policy", "synthetic_password_case", "salt_policy",
    secret_label="toy_secret_2", secret_bytes_len=12, salt_bytes_len=16,
    algorithm="pbkdf2_hmac", hash_name="sha256", cost_param=100000,
    expected_digest_obs="different_password_different_output")
# verifier metadata
add("c05_pbkdf2_algorithm_metadata", "verifier_format", "sample_verifier", "verifier_format",
    algorithm="pbkdf2_hmac", hash_name="sha256",
    expected_verifier_obs="algorithm_stored")
add("c06_pbkdf2_iteration_metadata", "verifier_format", "sample_verifier", "verifier_format",
    algorithm="pbkdf2_hmac", cost_param=100000,
    expected_verifier_obs="iterations_stored")
add("c07_pbkdf2_salt_metadata", "verifier_format", "sample_verifier", "verifier_format",
    salt_bytes_len=16, expected_verifier_obs="salt_stored")
add("c08_pbkdf2_digest_len_metadata", "verifier_format", "sample_verifier", "verifier_format",
    algorithm="pbkdf2_hmac", expected_digest_obs="digest_len_stored")
# verify success/wrong
add("c09_pbkdf2_verify_success", "kdf_policy", "fake_login_row", "kdf_policy",
    secret_label="toy_secret_1", algorithm="pbkdf2_hmac", cost_param=100000,
    expected_digest_obs="verify_success", expected_comparison_obs="compare_digest_match")
add("c10_pbkdf2_verify_wrong", "kdf_policy", "fake_login_row", "kdf_policy",
    secret_label="wrong_secret", algorithm="pbkdf2_hmac", cost_param=100000,
    expected_digest_obs="verify_fail", expected_comparison_obs="compare_digest_mismatch")
# iteration count
add("c11_pbkdf2_iteration_changes_output", "kdf_policy", "test_service", "kdf_policy",
    algorithm="pbkdf2_hmac", cost_param=200000,
    expected_digest_obs="iterations_change_output")
add("c12_pbkdf2_low_iteration_caveat", "kdf_policy", "test_service", "kdf_policy",
    algorithm="pbkdf2_hmac", cost_param=1000,
    expected_digest_obs="low_iteration_caveat", expected_comparison_obs="policy_warn")
# hash name
add("c13_pbkdf2_sha256_vs_sha512", "kdf_policy", "test_service", "kdf_policy",
    algorithm="pbkdf2_hmac", hash_name="sha512",
    expected_digest_obs="hash_name_matters")
# salt generation
add("c14_secrets_salt_generation", "salt_policy", "demo_account", "salt_policy",
    salt_bytes_len=16, expected_salt_obs="secrets_token_bytes")
add("c15_fixed_salt_negative", "salt_policy", "demo_account", "salt_policy",
    salt_bytes_len=16, expected_salt_obs="fixed_salt_footgun", expected_success=False,
    naive_should_fail=True)
add("c16_short_salt_caveat", "salt_policy", "demo_account", "salt_policy",
    salt_bytes_len=4, expected_salt_obs="short_salt_caveat")
add("c17_salt_uniqueness", "salt_policy", "synthetic_password_case", "salt_policy",
    salt_bytes_len=16, expected_salt_obs="salt_unique_in_corpus")
# scrypt
add("c18_scrypt_available", "kdf_policy", "sample_verifier", "kdf_policy",
    algorithm="scrypt", expected_digest_obs="scrypt_available_or_skip")
add("c19_scrypt_unavailable_skip", "kdf_policy", "sample_verifier", "kdf_policy",
    algorithm="scrypt", expected_success=None,
    expected_digest_obs="scrypt_optional_skip")
add("c20_scrypt_parameters", "kdf_policy", "sample_verifier", "kdf_policy",
    algorithm="scrypt", expected_digest_obs="scrypt_n_r_p_metadata")
add("c21_scrypt_memory_cost", "kdf_policy", "sample_verifier", "kdf_policy",
    algorithm="scrypt", expected_digest_obs="scrypt_memory_cost_caveat")
# compare_digest
add("c22_compare_digest_success", "compare_policy", "fake_login_row", "compare_policy",
    expected_comparison_obs="compare_digest_match")
add("c23_compare_digest_failure", "compare_policy", "fake_login_row", "compare_policy",
    expected_comparison_obs="compare_digest_mismatch")
add("c24_equality_compare_caveat", "compare_policy", "fake_login_row", "compare_policy",
    expected_comparison_obs="plain_equality_caveat", naive_should_fail=True)
# hex vs binary
add("c25_hex_vs_binary", "verifier_format", "sample_verifier", "verifier_format",
    expected_verifier_obs="hex_vs_binary_caveat")
# base64
add("c26_base64_verifier", "verifier_format", "sample_verifier", "verifier_format",
    expected_verifier_obs="base64_encoding")
# malformed verifier
add("c27_malformed_verifier", "verifier_format", "sample_verifier", "verifier_format",
    expected_success=False, expected_verifier_obs="malformed_verifier_parse_error")
add("c28_missing_algorithm", "verifier_format", "sample_verifier", "verifier_format",
    expected_success=False, expected_verifier_obs="missing_algorithm_metadata")
add("c29_missing_cost", "verifier_format", "sample_verifier", "verifier_format",
    expected_success=False, expected_verifier_obs="missing_cost_metadata")
add("c30_missing_salt", "verifier_format", "sample_verifier", "verifier_format",
    expected_success=False, expected_verifier_obs="missing_salt_metadata")
# encoding
add("c31_unicode_utf8", "encoding_caveat", "example_user", "encoding_caveat",
    secret_label="utf8_secret_é", secret_bytes_len=0,
    expected_encoding_obs="utf8_encoding")
add("c32_bytes_str_boundary", "encoding_caveat", "example_user", "encoding_caveat",
    expected_encoding_obs="bytes_str_boundary")
add("c33_normalization_not_applied", "encoding_caveat", "example_user", "encoding_caveat",
    expected_encoding_obs="normalization_not_silent")
add("c34_nul_byte", "encoding_caveat", "example_user", "encoding_caveat",
    expected_encoding_obs="nul_byte_caveat")
# input length
add("c35_long_input_policy", "input_length_caveat", "toy_secret", "input_length_caveat",
    secret_bytes_len=200, expected_encoding_obs="long_input_policy")
add("c36_bcrypt_72byte_not_tested", "bcrypt_not_tested", "toy_secret", "bcrypt_not_tested",
    secret_bytes_len=100, expected_encoding_obs="bcrypt_72byte_not_tested")
# argon2/bcrypt not in stdlib
add("c37_argon2_not_stdlib", "argon2_not_tested", "test_service", "argon2_not_tested",
    expected_digest_obs="argon2_not_stdlib")
add("c38_bcrypt_not_stdlib", "bcrypt_not_tested", "test_service", "bcrypt_not_tested",
    expected_digest_obs="bcrypt_not_stdlib")
# pepper
add("c39_pepper_not_tested", "production_truth_not_tested", "demo_account", "production_truth_not_tested",
    expected_digest_obs="pepper_not_tested")
# cache key smell
add("c40_password_cache_key_smell", "cache_key_caveat", "fake_login_row", "cache_key_caveat",
    expected_digest_obs="password_cache_key_smell", naive_should_fail=True)
# HMAC
add("c41_hmac_domain_separation", "hmac_caveat", "test_service", "hmac_caveat",
    expected_digest_obs="hmac_domain_separation")
add("c42_hmac_key_not_salt", "hmac_caveat", "test_service", "hmac_caveat",
    expected_digest_obs="hmac_key_not_salt")
# secrets vs random
add("c43_secrets_vs_random", "secrets_policy", "demo_account", "secrets_policy",
    expected_salt_obs="secrets_not_random")
add("c44_deterministic_salt_test", "secrets_policy", "demo_account", "secrets_policy",
    expected_salt_obs="deterministic_test_salt")
# timing not proof
add("c45_timing_not_proof", "production_truth_not_tested", "test_service", "production_truth_not_tested",
    expected_comparison_obs="timing_not_security_proof")
# password strength etc not tested
add("c46_password_strength_not_tested", "production_truth_not_tested", "example_user", "production_truth_not_tested",
    expected_digest_obs="password_strength_not_tested")
add("c47_breach_resistance_not_tested", "production_truth_not_tested", "example_user", "production_truth_not_tested",
    expected_digest_obs="breach_resistance_not_tested")
add("c48_rate_limiting_not_tested", "production_truth_not_tested", "fictional_admin", "production_truth_not_tested",
    expected_digest_obs="rate_limiting_not_tested")
add("c49_database_storage_not_tested", "production_truth_not_tested", "demo_account", "production_truth_not_tested",
    expected_digest_obs="database_storage_not_tested")
add("c50_production_auth_not_tested", "production_truth_not_tested", "fictional_admin", "production_truth_not_tested",
    expected_digest_obs="production_auth_not_tested")

with open("cases.json","w") as f: json.dump(CASES, f, indent=2)
print(f"Wrote {len(CASES)} cases")
