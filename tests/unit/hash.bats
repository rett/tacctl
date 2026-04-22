#!/usr/bin/env bats
# Unit tests for hash + password strength logic.

load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

# --- BCRYPT_COST bounds (loaded at source time) ------------------------------

@test "BCRYPT_COST: default is 12 when file missing" {
    [[ "$BCRYPT_COST" == "12" ]]
}

@test "BCRYPT_COST: accepts values in [10,14] from overrides" {
    conf_set bcrypt.cost 11
    unset BCRYPT_COST
    tacctl_source_lib
    [[ "$BCRYPT_COST" == "11" ]]

    conf_set bcrypt.cost 14
    unset BCRYPT_COST
    tacctl_source_lib
    [[ "$BCRYPT_COST" == "14" ]]
}

@test "BCRYPT_COST: clamps out-of-range to default 12" {
    # Hand-edited out-of-range values in the overrides file trip the clamp.
    printf 'bcrypt:\n  cost: 8\n' > "$TACCTL_OVERRIDES_FILE"
    unset BCRYPT_COST
    tacctl_source_lib
    [[ "$BCRYPT_COST" == "12" ]]

    printf 'bcrypt:\n  cost: 99\n' > "$TACCTL_OVERRIDES_FILE"
    unset BCRYPT_COST
    tacctl_source_lib
    [[ "$BCRYPT_COST" == "12" ]]
}

@test "BCRYPT_COST: non-numeric value clamps to default" {
    printf 'bcrypt:\n  cost: hello\n' > "$TACCTL_OVERRIDES_FILE"
    unset BCRYPT_COST
    tacctl_source_lib
    [[ "$BCRYPT_COST" == "12" ]]
}

# --- PASSWORD_MIN_LENGTH bounds ---------------------------------------------

@test "PASSWORD_MIN_LENGTH: default 12, clamps to [8,64]" {
    [[ "$PASSWORD_MIN_LENGTH" == "12" ]]

    conf_set password.min_length 8
    unset PASSWORD_MIN_LENGTH
    tacctl_source_lib
    [[ "$PASSWORD_MIN_LENGTH" == "8" ]]

    conf_set password.min_length 64
    unset PASSWORD_MIN_LENGTH
    tacctl_source_lib
    [[ "$PASSWORD_MIN_LENGTH" == "64" ]]

    printf 'password:\n  min_length: 7\n' > "$TACCTL_OVERRIDES_FILE"
    unset PASSWORD_MIN_LENGTH
    tacctl_source_lib
    [[ "$PASSWORD_MIN_LENGTH" == "12" ]]

    printf 'password:\n  min_length: 65\n' > "$TACCTL_OVERRIDES_FILE"
    unset PASSWORD_MIN_LENGTH
    tacctl_source_lib
    [[ "$PASSWORD_MIN_LENGTH" == "12" ]]
}

# --- SECRET_MIN_LENGTH bounds -----------------------------------------------

@test "SECRET_MIN_LENGTH: default 16, clamps to [16,128]" {
    [[ "$SECRET_MIN_LENGTH" == "16" ]]

    conf_set secret.min_length 16
    unset SECRET_MIN_LENGTH
    tacctl_source_lib
    [[ "$SECRET_MIN_LENGTH" == "16" ]]

    conf_set secret.min_length 128
    unset SECRET_MIN_LENGTH
    tacctl_source_lib
    [[ "$SECRET_MIN_LENGTH" == "128" ]]

    printf 'secret:\n  min_length: 15\n' > "$TACCTL_OVERRIDES_FILE"
    unset SECRET_MIN_LENGTH
    tacctl_source_lib
    [[ "$SECRET_MIN_LENGTH" == "16" ]]

    printf 'secret:\n  min_length: 129\n' > "$TACCTL_OVERRIDES_FILE"
    unset SECRET_MIN_LENGTH
    tacctl_source_lib
    [[ "$SECRET_MIN_LENGTH" == "16" ]]
}

# --- validate_password_strength ---------------------------------------------

@test "validate_password_strength: accepts 12+ char mixed password" {
    run validate_password_strength "Correct-Horse-Battery-Staple-42"
    assert_success
}

@test "validate_password_strength: rejects short password" {
    run validate_password_strength "short"
    assert_failure
    assert_output --partial "minimum is"
}

@test "validate_password_strength: rejects common-weak entries (case-insensitive)" {
    run validate_password_strength "Administrator"
    assert_failure
    assert_output --partial "common-weak list"

    # qwerty* and 12345* are wildcarded patterns in the case statement.
    run validate_password_strength "Qwerty123456"
    assert_failure
    run validate_password_strength "123456789012"
    assert_failure
}

@test "validate_password_strength: rejects password equal to username" {
    run validate_password_strength "ThisIsJSmithAlready" "ThisIsJSmithAlready"
    assert_failure
    assert_output --partial "username"
}

# --- generate_hash -----------------------------------------------------------

@test "generate_hash: produces hex-encoded bcrypt hash at configured cost" {
    # Speed up: use lowest cost (10) for this round-trip check.
    conf_set bcrypt.cost 10
    tacctl_source_lib

    run generate_hash "Correct-Horse-Battery-Staple-42"
    assert_success
    [[ -n "$output" ]]
    [[ "$output" =~ ^[0-9a-f]+$ ]]

    # Hex-decode and sanity-check the bcrypt prefix + cost field.
    local decoded
    decoded=$(python3 -c "import binascii, sys; print(binascii.unhexlify(sys.argv[1]).decode())" "$output")
    [[ "$decoded" =~ ^\$2b\$10\$ ]]

    # Independently verify with bcrypt.checkpw (bypassing verify_hash — see
    # the broken-verify_hash test below for why the built-in path can't be
    # used for round-trip).
    local check
    check=$(python3 -c '
import bcrypt, binascii, sys
pw = sys.argv[1].encode()
h = binascii.unhexlify(sys.argv[2])
print("MATCH" if bcrypt.checkpw(pw, h) else "NO_MATCH")
' "Correct-Horse-Battery-Staple-42" "$output")
    [[ "$check" == "MATCH" ]]
}

# --- verify_hash -------------------------------------------------------------

@test "verify_hash: round-trips with generate_hash" {
    conf_set bcrypt.cost 10
    tacctl_source_lib
    local pw="Correct-Horse-Battery-Staple-42"
    local hex
    hex=$(generate_hash "$pw")

    run verify_hash "$pw" "$hex"
    assert_success
    assert_output "MATCH"

    run verify_hash "wrong-password-42" "$hex"
    assert_success
    assert_output "NO_MATCH"
}

@test "verify_hash: reports INVALID_HASH on garbage hex" {
    run verify_hash "anything" "not-hex"
    assert_success
    assert_output "INVALID_HASH"
}

# Regression guard for the heredoc-vs-pipe stdin bug. If verify_hash is ever
# re-written to consume stdin twice (via `python3 - <<'PY'` + a pipe),
# `sys.stdin.buffer.read()` would silently return b'' and every verify would
# match against the empty password. This test catches that recurrence.
@test "verify_hash: does NOT treat every input as the empty password" {
    conf_set bcrypt.cost 10
    tacctl_source_lib
    local empty_hash
    empty_hash=$(generate_hash "")
    run verify_hash "not-empty" "$empty_hash"
    assert_success
    assert_output "NO_MATCH"
}

# --- normalize_bcrypt_hash ---------------------------------------------------

@test "normalize_bcrypt_hash: raw bcrypt → hex" {
    # A well-formed bcrypt hash (cost 10, all-zero salt/digest). Not valid
    # for verification, but should round-trip through the normalizer.
    local raw='$2b$10$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    run normalize_bcrypt_hash "$raw"
    assert_success
    [[ "$output" =~ ^[0-9a-f]+$ ]]
    # Round-trip: hex-decoded output should equal raw.
    local decoded
    decoded=$(python3 -c "import binascii, sys; print(binascii.unhexlify(sys.argv[1]).decode())" "$output")
    [[ "$decoded" == "$raw" ]]
}

@test "normalize_bcrypt_hash: already-hex stays hex (lowercased)" {
    # Hex of "$2b$10$" + 53*'.'
    local hex
    hex=$(python3 -c 'import binascii; print(binascii.hexlify(("$2b$10$"+"."*53).encode()).decode())')
    run normalize_bcrypt_hash "$hex"
    assert_success
    assert_output "$hex"
}

@test "normalize_bcrypt_hash: garbage input yields empty output" {
    run normalize_bcrypt_hash "not-a-hash"
    assert_success
    assert_output ""
}
