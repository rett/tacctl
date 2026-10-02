#!/usr/bin/env bats
# Unit tests for the listener model (plan 3.4): the listeners.<backend>.<name>
# schema of tacctl.yaml and its rejections (reserved TLS among them), the
# per-backend settings backends.tacacs.level and .metrics_address, the reader
# (backend_listeners), and the shipped unit files the TACACS+ backend runs a
# listener in. What the commands do with the model is in
# tests/integration/listeners.bats.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    tacctl_source_lib
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
}

listener() { # <name> <json>
    conf_set_json "listeners.tacacs.$1" "$2"
}

# --- Schema: what is accepted, and how it is stored --------------------------

@test "schema: a listener is stored with only what differs from the defaults" {
    listener mgmt '{"network": "tcp", "address": "10.1.0.1:4949", "role": "both", "tls": {"enabled": false}}'
    run cat "$OVERRIDES"
    assert_output --partial "mgmt:"
    assert_output --partial "network: tcp"
    assert_output --partial "address: 10.1.0.1:4949"
    refute_output --partial "role"
    refute_output --partial "tls"
}

@test "schema: the default listener set to its default is not written down" {
    listener default '{"network": "tcp", "address": "10.1.0.1:49"}'
    [[ -f "$OVERRIDES" ]]
    listener default '{"network": "tcp", "address": ":49"}'
    [[ ! -e "$OVERRIDES" ]]
    # The model is not a shipped default line either: it is built in, like backends.enabled.
    run conf_emit_defaults
    refute_output --partial "listeners"
}

@test "schema: tcp6 takes a bracketed IPv6 address, tcp an IPv4 one, both ':port'" {
    listener a '{"network": "tcp6", "address": "[::1]:4949"}'
    listener b '{"network": "tcp", "address": "127.0.0.1:4950"}'
    listener c '{"network": "tcp6", "address": ":4951"}'
    run listener d '{"network": "tcp", "address": "[::1]:4952"}'
    assert_failure
    assert_output --partial "tcp takes an IPv4 address"
    run listener d '{"network": "tcp6", "address": "127.0.0.1:4952"}'
    assert_failure
    assert_output --partial "tcp6 takes an IPv6 address"
}

@test "schema: the reserved TLS fields are accepted while tls.enabled is false" {
    listener tls '{"network": "tcp", "address": ":300", "tls": {"enabled": false, "cert": "/etc/tacctl/tls/cert.pem", "key": "/etc/tacctl/tls/key.pem", "ca": "/etc/tacctl/tls/ca.pem", "require_client_cert": true}}'
    run cat "$OVERRIDES"
    assert_output --partial "cert: /etc/tacctl/tls/cert.pem"
    assert_output --partial "require_client_cert: true"
    refute_output --partial "enabled"
    run _conf_validate_overrides_file
    assert_output ""
}

# --- Schema: rejections ------------------------------------------------------

@test "schema: tls.enabled: true is refused as reserved, and nothing is written" {
    run listener tls '{"network": "tcp", "address": ":300", "tls": {"enabled": true, "cert": "/a", "key": "/b"}}'
    assert_failure
    assert_output --partial "listeners.tacacs.tls: tls.enabled: true is reserved for a future release"
    [[ ! -e "$OVERRIDES" ]]
}

@test "schema: a hand-written tls.enabled: true is reported by the overrides walk" {
    printf 'listeners:\n  tacacs:\n    tls: {network: tcp, address: ":300", tls: {enabled: true}}\n' > "$OVERRIDES"
    run _conf_validate_overrides_file
    assert_output --partial "listeners.tacacs.tls: tls.enabled: true is reserved for a future release"
}

@test "schema: bad addresses, networks, roles, names, keys and backends are refused" {
    local case
    while IFS='|' read -r name json want; do
        run listener "$name" "$json"
        assert_failure
        assert_output --partial "$want"
    done <<'CASES'
x|{"network": "tcp", "address": "nonsense"}|must be host:port
x|{"network": "tcp", "address": ":0"}|port must be 1..65535
x|{"network": "tcp", "address": ":70000"}|port must be 1..65535
x|{"network": "tcp", "address": "host.example:49"}|is not an IP address
x|{"network": "tcp"}|address is required
x|{"network": "sctp", "address": ":300"}|network must be one of tcp, tcp6, udp, udp6
x|{"network": "udp", "address": ":300"}|the tacacs backend listens on tcp or tcp6 only
x|{"network": "tcp", "address": ":300", "role": "auth"}|a tacacs listener has role both
x|{"network": "tcp", "address": ":300", "role": "bogus"}|role must be one of auth, acct, both
x|{"network": "tcp", "address": ":300", "port": 49}|unknown keys ['port']
x|{"network": "tcp", "address": ":300", "tls": {"cipher": "x"}}|tls: unknown keys ['cipher']
x|{"network": "tcp", "address": ":300", "tls": {"enabled": "yes"}}|tls.enabled must be true or false
x|{"network": "tcp", "address": ":300", "metrics_address": "nope"}|metrics_address: must be host:port
Bad|{"network": "tcp", "address": ":300"}|a listener name is a lowercase letter
x|"tcp :300"|must be a mapping
CASES
    run conf_set_json listeners.ldap.auth '{"network": "udp", "address": ":1812"}'
    assert_failure
    assert_output --partial "'ldap' is not a backend with listeners"
    run conf_set_json listeners.tacacs '{"x": {"address": ":300"}}'
    assert_failure
    assert_output --partial "unknown config key"
    run conf_set listeners.tacacs.x ":300"
    assert_failure
    [[ ! -e "$OVERRIDES" ]]
}

@test "schema: two listeners on one network and address are refused, wildcards included" {
    # ':49' is every address of both families: nothing else can have port 49.
    run listener a '{"network": "tcp", "address": "10.1.0.1:49"}'
    assert_failure
    assert_output --partial "listeners.tacacs.a: tcp 10.1.0.1:49 is already used by listeners.tacacs.default (tcp :49)"
    run listener a '{"network": "tcp6", "address": "[::]:49"}'
    assert_failure
    [[ ! -e "$OVERRIDES" ]]

    listener a '{"network": "tcp", "address": "10.1.0.1:4949"}'
    run listener b '{"network": "tcp", "address": "10.1.0.1:4949"}'
    assert_failure
    assert_output --partial "already used by listeners.tacacs.a"
    run listener b '{"network": "tcp", "address": ":4949"}'
    assert_failure
    # Same port on another address is fine; so is the same listener again.
    listener b '{"network": "tcp", "address": "10.1.0.2:4949"}'
    listener a '{"network": "tcp", "address": "10.1.0.1:4949"}'
    # Moving the default onto a taken address is refused too.
    run listener default '{"network": "tcp", "address": "10.1.0.2:4949"}'
    assert_failure
    assert_output --partial "already used by"
}

@test "schema: a hand-written collision is reported by the overrides walk" {
    printf 'listeners:\n  tacacs:\n    a: {address: ":49"}\n    b: 5\n' > "$OVERRIDES"
    run _conf_validate_overrides_file
    assert_output --partial "listeners.tacacs.b: must be a mapping"
    assert_output --partial "listeners.tacacs.a: tcp :49 is already used by listeners.tacacs.default"
}

@test "schema: two listeners may not share a metrics address, except the sink" {
    listener a '{"network": "tcp", "address": ":300", "metrics_address": "127.0.0.1:9100"}'
    run listener b '{"network": "tcp", "address": ":301", "metrics_address": "127.0.0.1:9100"}'
    assert_failure
    assert_output --partial "metrics_address 127.0.0.1:9100 is already used by listeners.tacacs.a"
    listener b '{"network": "tcp", "address": ":301", "metrics_address": "127.0.0.1:0"}'
    listener c '{"network": "tcp", "address": ":302", "metrics_address": "127.0.0.1:0"}'
}

# --- Per-backend settings ----------------------------------------------------

@test "schema: backends.tacacs.level is an integer level; the default is not written down" {
    conf_set backends.tacacs.level 30
    run conf_get backends.tacacs.level
    assert_output "30"
    conf_set backends.tacacs.level 20
    [[ ! -e "$OVERRIDES" ]]
    run conf_set backends.tacacs.level debug
    assert_failure
    assert_output --partial "must be an integer"
    run conf_set backends.tacacs.level 101
    assert_failure
}

@test "schema: backends.tacacs.metrics_address is host:port; the default is not written down" {
    conf_set backends.tacacs.metrics_address ":9090"
    run conf_get backends.tacacs.metrics_address
    assert_output ":9090"
    conf_set backends.tacacs.metrics_address "localhost:9090"
    conf_set backends.tacacs.metrics_address "[::1]:9090"
    conf_set backends.tacacs.metrics_address "127.0.0.1:0"
    conf_set backends.tacacs.metrics_address "127.0.0.1:8080"
    [[ ! -e "$OVERRIDES" ]]
    run conf_set backends.tacacs.metrics_address "127.0.0.1"
    assert_failure
    assert_output --partial "must be host:port"
    run conf_set backends.tacacs.metrics_address "127.0.0.1:99999"
    assert_failure
}

@test "schema: per-backend settings do not disturb backends.enabled" {
    conf_set backends.tacacs.level 30
    run backends_enabled
    assert_success
    assert_output "tacacs"
    run _conf_validate_overrides_file
    assert_output ""
}

@test "the shell constants are the python renderer's and the unit's defaults" {
    run python3 <(_store_py; _model_py; _rendered_py; _listener_py; _render_tacacs_py | sed '/^if __name__/,$d'; \
        printf '%s\n' 'print(TACACS_LEVEL_DEFAULT, TACACS_METRICS_DEFAULT, TACACS_METRICS_SINK)')
    assert_success
    assert_output "${TACACS_LEVEL_DEFAULT} ${TACACS_METRICS_DEFAULT} ${TACACS_METRICS_SINK}"
    local unit="${TACCTL_SRC}/${TACACS_SHARE}/tacquito.service"
    grep -qxF "Environment=\"TACQUITO_LEVEL=${TACACS_LEVEL_DEFAULT}\"" "$unit"
    grep -qxF "Environment=\"TACQUITO_METRICS_ADDRESS=${TACACS_METRICS_DEFAULT}\"" "$unit"
    grep -qxF 'Environment="TACQUITO_NETWORK=tcp"' "$unit"
    grep -qxF 'Environment="TACQUITO_ADDRESS=:49"' "$unit"
    run python3 - <(_conf_schema_py) <<'PY'
import sys
exec(open(sys.argv[1]).read())
print(SCHEMA['backends.tacacs.level']['default'], SCHEMA['backends.tacacs.metrics_address']['default'])
print(LISTENER_BACKENDS['tacacs']['defaults'])
PY
    assert_line --index 0 "${TACACS_LEVEL_DEFAULT} ${TACACS_METRICS_DEFAULT}"
    assert_line --index 1 "{'default': {'network': 'tcp', 'address': ':49'}}"
}

# --- The reader --------------------------------------------------------------

@test "backend_listeners: the built-in default without a tacctl.yaml" {
    run backend_listeners tacacs
    assert_success
    assert_output "default"$'\t'"tcp"$'\t'":49"$'\t'"both"$'\t'"-"$'\t'"default"
}

@test "backend_listeners: the default first, then the others by name, with their source" {
    listener zeta '{"network": "tcp6", "address": "[::1]:4951"}'
    listener alpha '{"network": "tcp", "address": "127.0.0.1:4950", "metrics_address": "127.0.0.1:9100"}'
    listener default '{"network": "tcp", "address": "10.1.0.1:49"}'
    run backend_listeners tacacs
    assert_line --index 0 "default"$'\t'"tcp"$'\t'"10.1.0.1:49"$'\t'"both"$'\t'"-"$'\t'"override"
    assert_line --index 1 "alpha"$'\t'"tcp"$'\t'"127.0.0.1:4950"$'\t'"both"$'\t'"127.0.0.1:9100"$'\t'"override"
    assert_line --index 2 "zeta"$'\t'"tcp6"$'\t'"[::1]:4951"$'\t'"both"$'\t'"-"$'\t'"override"
}

@test "backend_listeners: an invalid hand-written entry is left out, an invalid default falls back" {
    printf 'listeners:\n  tacacs:\n    default: {address: "nonsense"}\n    bad: {network: udp, address: ":300"}\n    good: {address: ":301"}\n' > "$OVERRIDES"
    run backend_listeners tacacs
    assert_line --index 0 --partial "default"$'\t'"tcp"$'\t'":49"
    assert_line --index 1 --partial "good"$'\t'"tcp"$'\t'":301"
    refute_output --partial "bad"
}

# --- validate_listen_address: one check for the CLI and the schema -----------

@test "validate_listen_address: unchanged verdicts" {
    validate_listen_address tcp ":49"
    validate_listen_address tcp "10.1.0.1:49"
    validate_listen_address tcp6 "[::]:49"
    run validate_listen_address tcp "10.1.0.1"
    assert_failure
    assert_output --partial "Invalid tcp address: '10.1.0.1'"
    run validate_listen_address tcp "[::1]:49"
    assert_failure
    run validate_listen_address tcp6 "10.1.0.1:49"
    assert_failure
    run validate_listen_address tcp ":0"
    assert_failure
    run validate_listen_address tcp "example.net:49"
    assert_failure
}

# --- The shipped unit files --------------------------------------------------

# Everything from "# Security hardening" to the [Install] header.
hardening() {
    sed -n '/^# Security hardening/,/^\[Install\]/p' "$1"
}

@test "units: the template runs the same daemon under the same hardening as tacquito.service" {
    local unit="${TACCTL_SRC}/${TACACS_SHARE}/tacquito.service" tmpl="${TACCTL_SRC}/${TACACS_SHARE}/tacquito@.service"
    [[ -f "$unit" && -f "$tmpl" ]]
    diff <(hardening "$unit") <(hardening "$tmpl")
    diff <(sed -n '/^ExecStart=/,/^RestartSec=/p' "$unit") <(sed -n '/^ExecStart=/,/^RestartSec=/p' "$tmpl")
    # Ports below 1024 and the per-listener accounting log both stay possible.
    run hardening "$tmpl"
    assert_output --partial "AmbientCapabilities=CAP_NET_BIND_SERVICE"
    assert_output --partial "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"
    assert_output --partial "ReadWritePaths=/var/log/tacquito"
}

@test "units: both take every per-listener flag from the environment" {
    local f var
    for f in tacquito.service "tacquito@.service"; do
        for var in TACQUITO_NETWORK TACQUITO_ADDRESS TACQUITO_LEVEL TACQUITO_METRICS_ADDRESS TACQUITO_ACCT_LOG; do
            grep -qF "\${${var}}" "${TACCTL_SRC}/${TACACS_SHARE}/${f}"
        done
    done
}

@test "units: an instance belongs to tacquito.service and needs its rendered drop-in" {
    local tmpl="${TACCTL_SRC}/${TACACS_SHARE}/tacquito@.service"
    grep -qxF 'PartOf=tacquito.service' "$tmpl"
    grep -qxF 'WantedBy=tacquito.service' "$tmpl"
    grep -qxF 'AssertPathExists=/etc/systemd/system/tacquito@%i.service.d/tacctl.conf' "$tmpl"
    grep -qxF 'Environment="TACQUITO_ACCT_LOG=/var/log/tacquito/accounting-%i.log"' "$tmpl"
    # No address of its own: two processes on the default one cannot both bind.
    run grep -E '^Environment="TACQUITO_(NETWORK|ADDRESS)=' "$tmpl"
    assert_failure
    # No alias: systemd refuses a plain name for a template instance.
    run grep -E '^Alias=' "$tmpl" "${TACCTL_SRC}/${TACACS_SHARE}/tacquito.service"
    assert_failure
    grep -qxF 'WantedBy=multi-user.target' "${TACCTL_SRC}/${TACACS_SHARE}/tacquito.service"
}

@test "units: the paths tacctl derives for a listener" {
    [[ "$(_tacacs_unit default)" == "tacquito.service" ]]
    [[ "$(_tacacs_unit mgmt)" == "tacquito@mgmt.service" ]]
    [[ "$(_tacacs_dropin default)" == "${OVERRIDE_DIR}/tacctl.conf" ]]
    [[ "$(_tacacs_dropin mgmt)" == "${TACACS_UNIT_DIR}/tacquito@mgmt.service.d/tacctl.conf" ]]
    [[ "$(_tacacs_acct_log default)" == "$ACCT_LOG" ]]
    [[ "$(_tacacs_acct_log mgmt)" == "${TACCTL_LOG}/accounting-mgmt.log" ]]
    # Production paths, when nothing is overridden.
    production_paths() {
        (
            unset TACCTL_OVERRIDE_DIR TACCTL_SYSTEMD_DIR
            tacctl_source_lib
            echo "$SERVICE_FILE $TEMPLATE_FILE $(_tacacs_dropin default) $(_tacacs_dropin mgmt) $OVERRIDE_FILE"
        )
    }
    run production_paths
    assert_output "/etc/systemd/system/tacquito.service /etc/systemd/system/tacquito@.service /etc/systemd/system/tacquito.service.d/tacctl.conf /etc/systemd/system/tacquito@mgmt.service.d/tacctl.conf /etc/systemd/system/tacquito.service.d/tacctl-overrides.conf"
}

@test "logrotate: one stanza covers every listener's accounting log, restarting once" {
    local f="${TACCTL_SRC}/${TACACS_SHARE}/tacquito.logrotate"
    grep -qF '/var/log/tacquito/accounting.log /var/log/tacquito/accounting-*.log {' "$f"
    grep -qF 'sharedscripts' "$f"
    grep -qF 'systemctl restart tacquito' "$f"
}
