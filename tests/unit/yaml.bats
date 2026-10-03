#!/usr/bin/env bats
# Unit tests for the model's read helpers (read-only: fixtures unchanged).
#
# These are the readers every command uses for users, groups and scopes.
# They replaced helpers that parsed tacquito.yaml directly (list_scopes,
# scope_exists, read_scope_prefixes, read_scope_secret, scope_owning_prefix,
# read_user_scopes, count/list_users_in_scope, list_all_groups,
# get_group_privlvl); each test below is the one its predecessor had, asked
# of the model. The default setup reads the store; the last section asks the
# same questions with no store, where the model is built from tacquito.yaml.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
    load_fixture tacquito.multiscope.yaml
}

# --- model_scopes ------------------------------------------------------------

@test "model_scopes: enumerates every scope by name" {
    run model_scopes
    assert_success
    assert_line "prod"
    assert_line "prod-inner"
    assert_line "lab"
    assert_line "dmz"
    [[ "${#lines[@]}" -eq 4 ]]
}

# --- model_scope_exists ------------------------------------------------------

@test "model_scope_exists: returns 0 for known scope" {
    run model_scope_exists "prod"
    assert_success
    assert_output ""
    run model_scope_exists "lab"
    assert_success
}

@test "model_scope_exists: returns non-zero for unknown and empty" {
    run model_scope_exists "nonexistent"
    assert_failure
    run model_scope_exists ""
    assert_failure
}

# --- model_scope_prefixes ----------------------------------------------------

@test "model_scope_prefixes: emits canonical prefixes, longest first" {
    run model_scope_prefixes "prod"
    assert_success
    assert_output "10.0.0.0/8"

    run model_scope_prefixes "lab"
    assert_success
    # Sorted specificity-first (length DESC, then address ASC), so
    # /16 comes before /12. Matches tacquito's most-specific-wins
    # routing and what `scope routing` / `scope list` display.
    local expected="192.168.0.0/16
172.16.0.0/12"
    [[ "$output" == "$expected" ]]
}

@test "model_scope_prefixes: unknown scope → empty output" {
    run model_scope_prefixes "nonexistent"
    assert_success
    assert_output ""
}

@test "model_scope prefixes: the stored order is the render order, not the display order" {
    run model_scope lab prefixes
    assert_success
    assert_output "172.16.0.0/12
192.168.0.0/16"
}

# --- model_scope <name> secret -----------------------------------------------

@test "model_scope secret: returns raw key for named scope" {
    run model_scope "prod" secret
    assert_success
    assert_output "prod-secret-0123456789abcdef"
    run model_scope "lab" secret
    assert_success
    assert_output "lab-secret-0123456789abcdef"
}

@test "model_scope secret: unknown scope → empty, and says so with its status" {
    run model_scope "nonexistent" secret
    assert_failure 1
    assert_output ""
}

# --- model_prefix_owner: one scope per prefix --------------------------------

@test "model_prefix_owner: exact match on 10.0.0.0/8 → prod" {
    run model_prefix_owner "10.0.0.0/8"
    assert_success
    assert_output "prod"
}

@test "model_prefix_owner: exact match on 10.10.99.0/24 → prod-inner" {
    run model_prefix_owner "10.10.99.0/24"
    assert_success
    assert_output "prod-inner"
}

@test "model_prefix_owner: canonicalizes input before comparing" {
    # 10.10.99.5/24 canonicalizes to 10.10.99.0/24 → prod-inner.
    run model_prefix_owner "10.10.99.5/24"
    assert_success
    assert_output "prod-inner"
}

@test "model_prefix_owner: no match → empty output" {
    run model_prefix_owner "8.8.8.0/24"
    assert_success
    assert_output ""
}

@test "model_prefix_owner: a network inside an owned prefix is not owned" {
    # Ownership is of the exact network; overlap between scopes is allowed.
    run model_prefix_owner "10.10.0.0/16"
    assert_success
    assert_output ""
}

@test "model_prefix_owner: empty or unparseable input → empty" {
    run model_prefix_owner ""
    assert_success
    assert_output ""
    run model_prefix_owner "not-a-cidr"
    assert_success
    assert_output ""
}

# --- model_user <name> scopes ------------------------------------------------

@test "model_user scopes: lists scopes for known user in granted order" {
    run model_user "alice" scopes
    assert_success
    local expected="prod
lab"
    [[ "$output" == "$expected" ]]

    run model_user "carol" scopes
    assert_success
    expected="lab
dmz"
    [[ "$output" == "$expected" ]]
}

@test "model_user scopes: unknown user → empty, status 1" {
    run model_user "nobody" scopes
    assert_failure 1
    assert_output ""
}

@test "model_user_exists: known, unknown, empty" {
    run model_user_exists alice
    assert_success
    assert_output ""
    run model_user_exists nobody
    assert_failure
    run model_user_exists ""
    assert_failure
}

# --- model_scope_users -------------------------------------------------------

@test "model_scope_users: counts scope membership across users" {
    [[ "$(model_scope_users lab | wc -l)" -eq 3 ]]          # alice + bob + carol
    [[ "$(model_scope_users prod | wc -l)" -eq 1 ]]         # alice
    [[ "$(model_scope_users dmz | wc -l)" -eq 1 ]]          # carol
    [[ "$(model_scope_users prod-inner | wc -l)" -eq 0 ]]
}

@test "model_scope_users: returns member usernames, by name" {
    run model_scope_users "lab"
    assert_success
    assert_output "alice
bob
carol"

    run model_scope_users "prod"
    assert_success
    assert_output "alice"
}

# --- model_groups ------------------------------------------------------------

@test "model_groups: returns the groups defined in the fixture" {
    run model_groups
    assert_success
    assert_line "readonly"
    assert_line "operator"
    assert_line "superuser"
}

@test "model_group_exists: known, unknown, empty" {
    run model_group_exists operator
    assert_success
    run model_group_exists nosuch
    assert_failure
    run model_group_exists ""
    assert_failure
}

# --- model_group <name> priv_lvl ---------------------------------------------

@test "model_group priv_lvl: returns Cisco priv-lvl for built-in groups" {
    run model_group "readonly" priv_lvl
    assert_success
    assert_output "1"
    run model_group "operator" priv_lvl
    assert_success
    assert_output "7"
    run model_group "superuser" priv_lvl
    assert_success
    assert_output "15"
}

@test "model_group priv_lvl: unknown group → empty, status 1" {
    run model_group "nonexistent" priv_lvl
    assert_failure 1
    assert_output ""
}

# --- views: one interpreter run per table ------------------------------------

@test "model_user_rows: one line per user with group, status, password date and scopes" {
    run model_user_rows
    assert_success
    assert_output "alice|superuser|active|unknown|prod,lab
bob|operator|active|unknown|lab
carol|readonly|active|unknown|lab,dmz"
}

@test "model_user_info: fields and scope lines; never the hash; status 1 for an unknown user" {
    run model_user_info alice
    assert_success
    assert_output 'group=superuser
status=active
password_changed=unknown
priv_lvl=15
juniper_class=RW-CLASS
hash_type=$2b$12$
has_hash=1
scope=prod|1
scope=lab|1'
    refute_output --partial "$(model_user alice hash)"
    run model_user_info nobody
    assert_failure 1
    assert_output ""
}

@test "model_user_privlvl: the group's priv-lvl for an active user, nothing otherwise" {
    run model_user_privlvl bob
    assert_success
    assert_output "7"
    run model_user_privlvl nobody
    assert_success
    assert_output ""
    store_user_set bob disabled=true
    run model_user_privlvl bob
    assert_success
    assert_output ""
}

@test "model_group_rows: highest priv-lvl first, with user counts" {
    run model_group_rows
    assert_success
    assert_output "superuser|15|RW-CLASS|1
operator|7|OP-CLASS|1
readonly|1|RO-CLASS|1"
}

@test "model_group_rows: groups at the same priv-lvl keep the order 'sort -nr' gave them" {
    store_group_set alpha priv_lvl=7 juniper_class=A-CLASS
    store_group_set zeta priv_lvl=7 juniper_class=Z-CLASS
    run model_group_rows
    assert_success
    assert_output "superuser|15|RW-CLASS|1
zeta|7|Z-CLASS|0
operator|7|OP-CLASS|1
alpha|7|A-CLASS|0
readonly|1|RO-CLASS|1"
    # The pre-store listing piped its rows through this sort.
    [[ "$output" == "$(printf '%s\n' "$output" | LC_ALL=C sort -t'|' -k2 -nr)" ]]
}

@test "model_group_info: built-ins first in the shipped order, then the rest by name" {
    store_group_set zeta priv_lvl=3 juniper_class=Z-CLASS
    store_group_set alpha priv_lvl=9 juniper_class=A-CLASS
    run model_group_info
    assert_success
    assert_output "readonly|1|RO-CLASS
operator|7|OP-CLASS
superuser|15|RW-CLASS
alpha|9|A-CLASS
zeta|3|Z-CLASS"
}

@test "model_group_users: every member of a group, the accounting sink included" {
    run model_group_users operator
    assert_output "bob"
    run model_group_users nosuch
    assert_success
    assert_output ""
}

@test "scope-rows and scope-routing views: scope order follows the routing order" {
    run _model_view scope-rows lab
    assert_success
    # The fifth field is the scope's vendor attributes (RADIUS; none here).
    assert_output "prod-inner|10.10.99.0/24|0||
prod|10.0.0.0/8|1||
lab|192.168.0.0/16|3|yes|
|172.16.0.0/12|||
dmz|203.0.113.0/24|1||"
    run _model_view scope-routing lab
    assert_success
    assert_output "prod-inner|10.10.99.0/24|0|
dmz|203.0.113.0/24|1|
lab|192.168.0.0/16|3|yes
lab|172.16.0.0/12|3|yes
prod|10.0.0.0/8|1|"
}

@test "views never print a secret or a hash" {
    local view secret hash
    secret=$(model_scope lab secret)
    hash=$(model_user alice hash)
    for view in "user-rows" "user-info alice" "group-rows" "group-info" "scope-rows lab" \
                "scope-routing lab" "scope-lookup 10.10.99.1" "config-show" "status 16" \
                "linux-users lab" "validate full" "scope-devices lab" "vendor-rows" "vendor-gaps" \
                "device-problems lab 192.168.0.0/16"; do
        # shellcheck disable=SC2086  # view name plus its argument
        run _model_view $view
        assert_success
        refute_output --partial "$secret"
        refute_output --partial "$hash"
    done
}

@test "an unknown view is an error, not an empty answer" {
    run _model_view no-such-view
    assert_failure
    assert_output --partial "unknown view"
}

@test "SCOPE_PROTOCOLS matches the store schema's KNOWN_PROTOCOLS" {
    local known
    known=$(python3 -c "$(_store_py)
print(' '.join(KNOWN_PROTOCOLS))")
    [[ "$SCOPE_PROTOCOLS" == "$known" ]]
}

# --- the same readers with no store (legacy read-only mode) ------------------

legacy_mode() {
    rm -f "$STORE_FILE"
    _model_invalidate
    [[ "$(model_mode)" == "legacy" ]]
}

@test "legacy mode: scope readers answer from tacquito.yaml" {
    legacy_mode
    [[ "$(model_scopes | wc -l)" -eq 4 ]]
    run model_scope_exists prod-inner
    assert_success
    run model_scope_exists nonexistent
    assert_failure
    [[ "$(model_scope prod secret)" == "prod-secret-0123456789abcdef" ]]
    [[ "$(model_scope_prefixes lab)" == "192.168.0.0/16
172.16.0.0/12" ]]
    [[ "$(model_prefix_owner 10.10.99.5/24)" == "prod-inner" ]]
    [[ "$(model_scope_users lab)" == "alice
bob
carol" ]]
}

@test "legacy mode: user and group readers answer from tacquito.yaml" {
    legacy_mode
    [[ "$(model_user alice scopes)" == "prod
lab" ]]
    [[ "$(model_user carol group)" == "readonly" ]]
    [[ "$(model_group operator priv_lvl)" == "7" ]]
    [[ "$(model_user_privlvl alice)" == "15" ]]
    [[ "$(model_user_rows)" == "alice|superuser|active|unknown|prod,lab
bob|operator|active|unknown|lab
carol|readonly|active|unknown|lab,dmz" ]]
}

@test "legacy mode: a user pointing at a missing scope is reported, not hidden" {
    legacy_mode
    sed -i 's/^      - dmz$/      - nosuchscope/' "$TACCTL_CONFIG"
    _model_invalidate
    run model_user_info carol
    assert_success
    assert_line "scope=lab|1"
    assert_line "scope=nosuchscope|0"
    run _model_view status 16
    assert_line "orphan=carol:nosuchscope"
    run _model_view validate full
    assert_line "ERROR:User 'carol' references nonexistent scope 'nosuchscope'"
}
