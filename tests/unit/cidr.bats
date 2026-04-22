#!/usr/bin/env bats
# Unit tests for CIDR helpers: validate_cidr, canonicalize_cidr,
# cidr_to_cisco_wildcard, parse_cidr_list, sort_cidrs_by_specificity.

load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

# --- validate_cidr -----------------------------------------------------------

@test "validate_cidr: accepts IPv4 networks" {
    run validate_cidr "10.0.0.0/8"
    assert_success
    run validate_cidr "192.168.1.0/24"
    assert_success
    run validate_cidr "10.1.5.5/32"
    assert_success
}

@test "validate_cidr: accepts IPv6 networks" {
    run validate_cidr "2001:db8::/32"
    assert_success
    run validate_cidr "fe80::/10"
    assert_success
}

@test "validate_cidr: accepts non-strict host-bits-set forms" {
    run validate_cidr "10.1.5.5/24"
    assert_success
}

@test "validate_cidr: rejects garbage" {
    run validate_cidr "not-a-cidr"
    assert_failure
    run validate_cidr "10.0.0.0/33"
    assert_failure
    run validate_cidr "999.0.0.0/8"
    assert_failure
    run validate_cidr ""
    assert_failure
}

# --- canonicalize_cidr -------------------------------------------------------

@test "canonicalize_cidr: zeros host bits on IPv4" {
    run canonicalize_cidr "10.1.5.5/24"
    assert_output "10.1.5.0/24"
    run canonicalize_cidr "172.16.1.99/16"
    assert_output "172.16.0.0/16"
}

@test "canonicalize_cidr: lowercases and compresses IPv6" {
    run canonicalize_cidr "2001:DB8::/32"
    assert_output "2001:db8::/32"
    run canonicalize_cidr "2001:0db8:0000::/48"
    assert_output "2001:db8::/48"
}

@test "canonicalize_cidr: preserves already-canonical forms" {
    run canonicalize_cidr "10.0.0.0/8"
    assert_output "10.0.0.0/8"
    run canonicalize_cidr "2001:db8::/32"
    assert_output "2001:db8::/32"
}

@test "canonicalize_cidr: invalid input produces empty output" {
    run canonicalize_cidr "not-a-cidr"
    assert_output ""
    run canonicalize_cidr ""
    assert_output ""
}

# --- cidr_to_cisco_wildcard --------------------------------------------------

@test "cidr_to_cisco_wildcard: emits 'network wildcard' form for IPv4" {
    run cidr_to_cisco_wildcard "10.0.0.0/8"
    assert_output "10.0.0.0 0.255.255.255"
    run cidr_to_cisco_wildcard "192.168.1.0/24"
    assert_output "192.168.1.0 0.0.0.255"
    run cidr_to_cisco_wildcard "10.1.2.3/32"
    assert_output "10.1.2.3 0.0.0.0"
}

@test "cidr_to_cisco_wildcard: returns empty for IPv6" {
    run cidr_to_cisco_wildcard "2001:db8::/32"
    assert_output ""
}

# --- parse_cidr_list ---------------------------------------------------------

@test "parse_cidr_list: splits on commas, canonicalizes, dedupes" {
    run parse_cidr_list "10.0.0.0/8, 192.168.1.5/24, 10.0.0.0/8"
    assert_success
    # Order preserved; dedupe on canonical form; whitespace trimmed.
    local expected="10.0.0.0/8
192.168.1.0/24"
    [[ "$output" == "$expected" ]]
}

@test "parse_cidr_list: empty input → empty output" {
    run parse_cidr_list ""
    assert_success
    assert_output ""
}

@test "parse_cidr_list: aborts on invalid entry" {
    run parse_cidr_list "10.0.0.0/8, not-a-cidr"
    assert_failure
}

# --- sort_cidrs_by_specificity ----------------------------------------------

@test "sort_cidrs_by_specificity: IPv4 before IPv6" {
    run sort_cidrs_by_specificity <<< "2001:db8::/32
10.0.0.0/8"
    assert_success
    local expected="10.0.0.0/8
2001:db8::/32"
    [[ "$output" == "$expected" ]]
}

@test "sort_cidrs_by_specificity: supernet before equal-broadcast subnet" {
    # 10.0.0.0/8 and 10.0.0.0/24 share network address 10.0.0.0.
    # The /24 has broadcast 10.0.0.255 (smaller int); /8 has 10.255.255.255.
    # Sort is by (version, broadcast_asc, network_asc): /24 comes first.
    run sort_cidrs_by_specificity <<< "10.0.0.0/8
10.0.0.0/24"
    assert_success
    local expected="10.0.0.0/24
10.0.0.0/8"
    [[ "$output" == "$expected" ]]
}

@test "sort_cidrs_by_specificity: drops invalid lines silently" {
    # Sort is (version, broadcast_asc, network_asc). Broadcasts:
    # 10.0.0.0/8 = 10.255.255.255 (smaller), 192.168.0.0/16 = 192.168.255.255.
    run sort_cidrs_by_specificity <<< "10.0.0.0/8
garbage
192.168.0.0/16"
    assert_success
    local expected="10.0.0.0/8
192.168.0.0/16"
    [[ "$output" == "$expected" ]]
}
