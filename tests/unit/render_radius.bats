#!/usr/bin/env bats
# Unit tests for the RADIUS backend's pure pieces (lib/backends/radius.sh):
# hash conversion, secret quoting, client and user rendering, the vendor
# attributes (clients per prefix and per tagged address, the control-list
# values, the policy, the dictionary), the filter policy, the render id,
# golden output for both distro layouts, the notes, the listener model for
# 'radius', the unit drop-in and the read-only contract verbs. What the commands do with it is in
# tests/integration/radius.bats; what real FreeRADIUS does with the output is
# verified in containers (tests/README.md, docs/radius-notes.md).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

FIX="${BATS_TEST_DIRNAME}/../fixtures"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd systemctl
    tacctl_source_lib
    OUT="${BATS_TEST_TMPDIR}/out"
    MODEL="${BATS_TEST_TMPDIR}/model.json"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    mkdir -p "$OUT"
}

# Load a store fixture and dump its model to $MODEL.
use_store() {
    cp "${FIX}/$1" "$STORE_FILE"
    _model_invalidate
    model_dump > "$MODEL"
}

# Edit the model of the radius fixture: edit_model '<python statements on m>'
edit_model() {
    use_store store.radius.yaml
    python3 - "$MODEL" "$1" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
exec(sys.argv[2])
json.dump(m, open(sys.argv[1], 'w'))
PY
}

render() {
    render_radius_config "$MODEL" "$OUT"
}

# Render as a distro family with the production paths (no test overrides).
render_as() {
    (
        unset TACCTL_RADIUS_DIR TACCTL_RADIUS_LOG TACCTL_RADIUS_BIN TACCTL_RADIUS_DICT
        export TACCTL_RADIUS_FAMILY="$1"
        # shellcheck disable=SC1090
        source "$TACCTL_BIN_SCRIPT"
        render_radius_config "$MODEL" "$OUT"
    )
}

quote() {
    printf '%s' "$1" | _radius_python secret
}

hexof() {
    printf '%s' "$1" | od -An -tx1 | tr -d ' \n'
}

# --- hash conversion ---------------------------------------------------------

@test "hash: the stored hex becomes the \$2b\$ string crypt(3) takes" {
    local raw='$2b$12$abcdefghijklmnopqrstuuLkZ0xN8Zr5Qe9u1F0mWqkO4d2c3V4sW'
    run _radius_python hash-raw "$(hexof "$raw")"
    assert_success
    assert_output "$raw"
    run _radius_python hash-raw "$(hexof '$2a$10$abc./XYZ')"
    assert_output '$2a$10$abc./XYZ'
}

@test "hash: what is not hex, or decodes to something with a quote or a backslash, is refused" {
    run _radius_python hash-raw "zz"
    assert_failure
    run _radius_python hash-raw "$(hexof '$2b$12$abc"def')"
    assert_failure
    assert_output --partial "no bcrypt hash has"
    run _radius_python hash-raw "$(hexof '$2b$12$abc\def')"
    assert_failure
    run _radius_python hash-raw "$(hexof 'plaintext')"
    assert_failure
}

# --- secret quoting ----------------------------------------------------------
# docs/radius-notes.md has the daemon's side of each of these.

@test "secret: without a backslash it is single-quoted, and only ' is escaped" {
    run quote 'abc+/=._-0123456789'
    assert_output "'abc+/=._-0123456789'"
    run quote 'two words #1 ; {x} %{User-Name}'
    assert_output "'two words #1 ; {x} %{User-Name}'"
    run quote 'a"b'
    assert_output "'a\"b'"
    run quote "it's"
    assert_output "'it\\'s'"
    # '${...}' is expanded inside double quotes, never inside single ones.
    run quote 'a${confdir}b $ENV{HOME}'
    assert_output "'a\${confdir}b \$ENV{HOME}'"
}

@test "secret: with a backslash it is double-quoted, backslash and \" escaped" {
    run quote 'a\b'
    assert_output '"a\\b"'
    run quote 'ends\'
    assert_output '"ends\\"'
    run quote 'a\"b'\''c'
    assert_output '"a\\\"b'\''c"'
    run quote 'back\nslash-n'
    assert_output '"back\\nslash-n"'
}

@test "secret: a backslash together with a dollar sign has no safe form and is refused" {
    run quote 'a\b$c'
    assert_failure
    assert_output ""
    run quote ''
    assert_failure
    run quote $'tab\there'
    assert_failure
}

@test "secret: a scope whose secret cannot be written refuses the render, naming the scope and not the secret" {
    edit_model 'm["scopes"]["prod"]["secret"] = "top\\\\secret$value-0123456789"'
    run render
    assert_failure
    assert_output --partial "scope 'prod'"
    assert_output --partial "tacctl scope protocols prod set tacacs"
    refute_output --partial 'secret$value'
    [[ ! -e "${OUT}/conf" ]]
}

@test "secret: the same secret in a TACACS+-only scope does not stop the render" {
    edit_model 'm["scopes"]["legacy"]["secret"] = "top\\\\secret$value-0123456789"'
    run render
    assert_success
    refute grep -q 'secret\$value' "${OUT}/conf"
}

# --- clients -----------------------------------------------------------------

@test "clients: one per prefix of every scope RADIUS serves, most specific first, with the scope's secret" {
    use_store store.radius.yaml
    render
    run bash -c 'sed -n "/One client per prefix/,/authorize {/p" "$1" | grep -E "^\s+(client|ipaddr|ipv6addr|secret|tacctl_scope) "' _ "${OUT}/conf"
    assert_output "$(cat <<'EOF'
	client prod-inner.1 {
		ipaddr = 10.10.99.0/24
		secret = "inner\\secret \"quoted\" 0123456789"
		tacctl_scope = "prod-inner"
	client wifi.1 {
		ipaddr = 10.20.0.0/16
		secret = 'wifi-radius-only-0123456789'
		tacctl_scope = "wifi"
	client prod.1 {
		ipaddr = 10.0.0.0/8
		secret = 'prod-secret-0123456789abcdef'
		tacctl_scope = "prod"
	client lab.1 {
		ipaddr = 172.16.0.0/12
		secret = 'it\'s a "lab" secret ${confdir} #1'
		tacctl_scope = "lab"
	client lab.2 {
		ipaddr = 192.168.0.0/16
		secret = 'it\'s a "lab" secret ${confdir} #1'
		tacctl_scope = "lab"
	client lab.3 {
		ipv6addr = fd00:10::/64
		secret = 'it\'s a "lab" secret ${confdir} #1'
		tacctl_scope = "lab"
EOF
)"
}

@test "clients: a scope whose protocols filter does not name radius has no client and its secret is not in the file" {
    use_store store.radius.yaml
    render
    refute grep -q 'legacy' "${OUT}/conf"
    refute grep -q '198.51.100' "${OUT}/conf"
    refute grep -q 'legacy' "${OUT}/users"
}

@test "clients: no scope for RADIUS renders a server without clients" {
    edit_model 'for s in m["scopes"].values(): s["protocols"] = ["tacacs"]'
    run render
    assert_success
    refute grep -q '^\sclient ' "${OUT}/conf"
    grep -q '^server tacctl {' "${OUT}/conf"
    refute grep -q '^[a-z]' "${OUT}/users"
}

# --- users -------------------------------------------------------------------

@test "users: one entry per user and served scope, with the hash and the group's reply items" {
    use_store store.radius.yaml
    render
    local rid
    rid=$(sed -n 's/^# render id: //p' "${OUT}/conf")
    [[ "$rid" =~ ^[0-9a-f]{16}$ ]]
    run grep -c '^[A-Za-z0-9_-]' "${OUT}/users"
    assert_output "6"
    run grep -A3 "^bob" "${OUT}/users"
    assert_output "$(cat <<EOF
bob	Tmp-String-0 == "${rid}/lab", Crypt-Password := "\$2a\$12\$bob..........................................................", Tacctl-Priv-Lvl := 7, Tacctl-Juniper-Class := "OP-CLASS", Tacctl-WTI-Super := 1
	Service-Type = NAS-Prompt-User,
	Fall-Through = No
EOF
)"
    # alice: three served scopes, superuser.
    run grep -c "^alice" "${OUT}/users"
    assert_output "3"
    run grep -A1 "^alice	Tmp-String-0 == \"${rid}/wifi\"" "${OUT}/users"
    assert_line --index 0 --partial ', Tacctl-Priv-Lvl := 15, Tacctl-Juniper-Class := "RW-CLASS", Tacctl-WTI-Super := 3'
    assert_line --index 1 "	Service-Type = Administrative-User,"
    # erin: a custom group (priv 10: the SuperUser band).
    run grep "^erin	Tmp-String-0 == \"${rid}/prod-inner\"" "${OUT}/users"
    assert_output --partial ', Tacctl-Priv-Lvl := 10, Tacctl-Juniper-Class := "NETOPS_class-1", Tacctl-WTI-Super := 2'
}

@test "users: the reply is Service-Type alone; vendor values are check items for the control list, never reply items" {
    use_store store.radius.yaml
    render
    # Every reply line of every entry: Service-Type or Fall-Through.
    run bash -c 'grep -E "^\s" "$1" | sed "s/,\$//" | sort -u' _ "${OUT}/users"
    assert_output "$(printf '\tFall-Through = No\n\tService-Type = Administrative-User\n\tService-Type = NAS-Prompt-User')"
    run bash -c 'grep -v "^#" "$1" | grep -E "(^|[^-])(Cisco-AVPair|Juniper-Local-User-Name|WTI-Super)"' _ "${OUT}/users"
    assert_output ""
    # The values ride on the check line with ':=' (set in the control list).
    run grep -c ', Tacctl-Priv-Lvl := [0-9]*, Tacctl-Juniper-Class := "[A-Za-z0-9_-]*", Tacctl-WTI-Super := [0-3]$' "${OUT}/users"
    assert_output "6"
}

@test "users: disabled users, the accounting sink and users with only TACACS+ scopes have no entry" {
    use_store store.radius.yaml
    render
    refute grep -q '^carol' "${OUT}/users"
    refute grep -q '^root' "${OUT}/users"
    refute grep -q '^dave' "${OUT}/users"
    # ...and their hashes are not in the file at all.
    refute grep -q 'carol\.\.\.' "${OUT}/users"
}

@test "users: a name FreeRADIUS reads as a default for everyone refuses the render" {
    edit_model 'm["users"]["DEFAULT-admin"] = dict(m["users"]["alice"])'
    run render
    assert_failure
    assert_output --partial "user 'DEFAULT-admin' cannot be served over RADIUS"
    # Out of RADIUS's scopes it is nobody's problem.
    edit_model 'm["users"]["DEFAULT-admin"] = dict(m["users"]["dave"])'
    run render
    assert_success
}

@test "render id: binds the two files, is stable, and changes with either file's content" {
    use_store store.radius.yaml
    render
    local rid again
    rid=$(sed -n 's/^# render id: //p' "${OUT}/conf")
    grep -q "&Tmp-String-0 := \"${rid}/%{client:tacctl_scope}\"" "${OUT}/conf"
    run grep -c "Tmp-String-0 == \"${rid}/" "${OUT}/users"
    assert_output "6"
    refute grep -q '@TACCTL_RENDER_ID@' "${OUT}/conf" "${OUT}/users"
    cp "${OUT}/conf" "${OUT}/conf.1"; cp "${OUT}/users" "${OUT}/users.1"
    render
    cmp "${OUT}/conf" "${OUT}/conf.1"
    cmp "${OUT}/users" "${OUT}/users.1"
    # A change that touches only the users file moves the id in both.
    edit_model 'm["users"]["bob"]["disabled"] = True'
    render
    again=$(sed -n 's/^# render id: //p' "${OUT}/conf")
    [[ "$again" != "$rid" ]]
    refute grep -q "$rid" "${OUT}/users"
}

# --- filters -----------------------------------------------------------------

@test "filters: deny and allow become a policy that answers nothing, used for authentication and accounting" {
    use_store store.radius.yaml
    render
    grep -qF 'if ((&Packet-Src-IP-Address && (&Packet-Src-IP-Address <= 10.66.0.0/16)) || (&Packet-Src-IPv6-Address && (&Packet-Src-IPv6-Address <= fd00:10::bad/128))) {' "${OUT}/conf"
    grep -qF 'if (!((&Packet-Src-IP-Address && (&Packet-Src-IP-Address <= 10.0.0.0/8)) || ' "${OUT}/conf"
    grep -qF '&Response-Packet-Type := Do-Not-Respond' "${OUT}/conf"
    # Deny is tested before allow.
    local deny allow
    deny=$(grep -n 'filters.deny' "${OUT}/conf" | cut -d: -f1)
    allow=$(grep -n 'filters.allow' "${OUT}/conf" | cut -d: -f1)
    (( deny < allow ))
    run grep -c '^		tacctl_filter$' "${OUT}/conf"
    assert_output "2"
}

@test "filters: none means no policy section and no call of it" {
    edit_model 'm["filters"] = {"allow": [], "deny": []}'
    render
    refute grep -q '^\s*tacctl_filter' "${OUT}/conf"
    refute grep -q '^policy' "${OUT}/conf"
}

# --- the policy and what is not there ----------------------------------------

# --- vendor attributes -------------------------------------------------------

# The client{} block of <name> in the rendered conf, its lines trimmed.
client_block() {
    sed -n "/^\tclient $1 {/,/^\t}/p" "${OUT}/conf" | sed 's/^\s*//'
}

@test "vendor clients: every client says its scope, 'generic', and no for every vendor when nothing is enabled" {
    use_store store.radius.yaml
    render
    run client_block prod.1
    assert_output "$(cat <<'EOF'
client prod.1 {
ipaddr = 10.0.0.0/8
secret = 'prod-secret-0123456789abcdef'
tacctl_scope = "prod"
tacctl_device = "generic"
tacctl_send_cisco = "no"
tacctl_send_juniper = "no"
tacctl_send_wti = "no"
}
EOF
)"
    run grep -c 'tacctl_send_[a-z]* = "yes"' "${OUT}/conf"
    assert_output "0"
}

@test "vendor clients: a scope's enabled vendors are yes on its generic clients only" {
    edit_model 'm["scopes"]["lab"]["vendor_attrs"] = ["cisco", "wti"]'
    render
    local c
    for c in lab.1 lab.2 lab.3; do
        run client_block "$c"
        assert_line 'tacctl_send_cisco = "yes"'
        assert_line 'tacctl_send_juniper = "no"'
        assert_line 'tacctl_send_wti = "yes"'
    done
    run client_block prod.1
    assert_line 'tacctl_send_cisco = "no"'
}

@test "vendor clients: a tagged address is a client of its own, before its prefix, sending its own vendor only" {
    edit_model 'm["scopes"]["prod"]["vendor_attrs"] = ["cisco", "juniper", "wti"]; m["scopes"]["prod"]["devices"] = {"10.1.2.3/32": "wti", "10.2.0.0/16": "juniper"}'
    render
    run client_block prod.wti.1
    assert_output "$(cat <<'EOF'
client prod.wti.1 {
ipaddr = 10.1.2.3/32
secret = 'prod-secret-0123456789abcdef'
tacctl_scope = "prod"
tacctl_device = "wti"
tacctl_send_cisco = "no"
tacctl_send_juniper = "no"
tacctl_send_wti = "yes"
}
EOF
)"
    run client_block prod.juniper.1
    assert_line 'ipaddr = 10.2.0.0/16'
    assert_line 'tacctl_send_cisco = "no"'
    assert_line 'tacctl_send_juniper = "yes"'
    assert_line 'tacctl_send_wti = "no"'
    # Most specific first: the /32 and the /16 before the scope's /8.
    run awk '$1 == "client" && $2 ~ /^prod\./ { print $2 }' "${OUT}/conf"
    assert_output "$(printf 'prod.wti.1\nprod.juniper.1\nprod.1')"
}

@test "vendor clients: a tag on a CIDR that is also a prefix of its scope is one client, the tagged one" {
    edit_model 'm["scopes"]["prod-inner"]["devices"] = {"10.10.99.0/24": "cisco"}'
    render
    run grep -c 'ipaddr = 10.10.99.0/24$' "${OUT}/conf"
    assert_output "1"
    run client_block prod-inner.cisco.1
    assert_line 'tacctl_device = "cisco"'
    refute grep -q 'client prod-inner.1 ' "${OUT}/conf"
}

@test "vendor clients: the tags of a scope RADIUS does not serve are not rendered" {
    edit_model 'm["scopes"]["legacy"]["devices"] = {"198.51.100.7/32": "cisco"}; m["scopes"]["legacy"]["vendor_attrs"] = ["cisco"]'
    render
    refute grep -q '198.51.100' "${OUT}/conf"
}

@test "vendor policy: each vendor's attribute is added only on a client's exact yes, from the control list, inside the accept path" {
    use_store store.radius.yaml
    render
    local body
    body=$(sed -n '/^\tpost-auth {/,/^\t\tPost-Auth-Type REJECT {/p' "${OUT}/conf")
    run grep -cE '^\s+if \(\("%\{client:tacctl_send_(cisco|juniper|wti)\}" == "yes"\) && &control:Tacctl-' <<< "$body"
    assert_output "3"
    grep -qF '&Cisco-AVPair := "shell:priv-lvl=%{control:Tacctl-Priv-Lvl}"' <<< "$body"
    grep -qF '&Juniper-Local-User-Name := &control:Tacctl-Juniper-Class' <<< "$body"
    grep -qF '&WTI-Super := &control:Tacctl-WTI-Super' <<< "$body"
    # The three are inside the branch a filtered packet does not take, before the auth log.
    run awk '/if \(!&control:Response-Packet-Type\)/ {in_=1} in_ && /update reply/ {n++} in_ && /tacctl_auth/ {print n; exit}' <<< "$body"
    assert_output "3"
    # Nothing tacctl-internal is ever put into the reply, and a reject strips every vendor attribute.
    run bash -c 'sed -n "/update reply {/,/}/p" "$1" | grep -E "^\s+&Tacctl-"' _ "${OUT}/conf"
    assert_output ""
    local reject a
    reject=$(sed -n '/Post-Auth-Type REJECT {/,/^\t\t}/p' "${OUT}/conf")
    for a in Service-Type Cisco-AVPair Juniper-Local-User-Name WTI-Super; do
        grep -qF "&${a} !* ANY" <<< "$reject"
    done
}

@test "auth log: one line per accept and reject names the client's device tag" {
    use_store store.radius.yaml
    render
    grep -qF 'scope=%{client:tacctl_scope} device=%{client:tacctl_device} client=' "${OUT}/conf"
}

@test "dictionary: the package's main dictionary first, then WTI-Super and tacctl's internal attributes" {
    use_store store.radius.yaml
    render
    [[ "$(grep -v '^#' "${OUT}/dictionary" | awk 'NF' | head -1)" == "\$INCLUDE ${TACCTL_RADIUS_DICT}" ]]
    run cat "${OUT}/dictionary"
    assert_line "$(printf 'VENDOR\t\tWTI\t\t\t24496')"
    assert_line "$(printf 'ATTRIBUTE\tWTI-Super\t\t41\tinteger')"
    local v
    for v in "ViewOnly	0" "User	1" "SuperUser	2" "Administrator	3"; do
        assert_line "$(printf 'VALUE\t\tWTI-Super\t\t%s' "$v")"
    done
    # Internal attributes: in the site-local range FreeRADIUS never encodes.
    run awk '$1 == "ATTRIBUTE" && $2 ~ /^Tacctl-/ { print $2, $3, $4 }' "${OUT}/dictionary"
    assert_output "$(printf 'Tacctl-Priv-Lvl 3990 integer\nTacctl-Juniper-Class 3991 string\nTacctl-WTI-Super 3992 integer')"
    grep -q 'https://ftp.wti.com/InfoCenter/rsa/dictionary/dictionary.wti' "${OUT}/dictionary"
    # Nothing of the model is in it.
    refute grep -qE 'prod|alice|secret-0123' "${OUT}/dictionary"
}

@test "render id: changes when the dictionary changes, and the dictionary itself does not carry it" {
    use_store store.radius.yaml
    render
    local rid again
    rid=$(sed -n 's/^# render id: //p' "${OUT}/conf")
    refute grep -q "$rid" "${OUT}/dictionary"
    render_as debian
    again=$(sed -n 's/^# render id: //p' "${OUT}/conf")
    grep -q '^\$INCLUDE /usr/share/freeradius/dictionary$' "${OUT}/dictionary"
    ( export TACCTL_RADIUS_FAMILY=debian; unset TACCTL_RADIUS_DIR TACCTL_RADIUS_LOG TACCTL_RADIUS_BIN
      export TACCTL_RADIUS_DICT=/somewhere/else/dictionary
      source "$TACCTL_BIN_SCRIPT"; render_radius_config "$MODEL" "$OUT" )
    grep -q '^\$INCLUDE /somewhere/else/dictionary$' "${OUT}/dictionary"
    [[ "$(sed -n 's/^# render id: //p' "${OUT}/conf")" != "$again" ]]
}

@test "WTI-Super: the Python bands equal the bash mapping for every privilege level" {
    local lvl py name num
    for lvl in $(seq 0 15); do
        py=$(_radius_python wti-super "$lvl")
        name=$(wti_access_level_for_privlvl "$lvl")
        num=$(wti_super_for_privlvl "$lvl")
        [[ "$py" == "${num} ${name}" ]] || { echo "priv-lvl ${lvl}: python '${py}', bash '${num} ${name}'"; return 1; }
    done
}

@test "notes: how many scopes send a vendor attribute, and how many addresses are tagged" {
    use_store store.radius.yaml
    run _radius_notes
    # Five scopes, four of them served over RADIUS; none enables anything.
    assert_line "vendors|0|4|0"
    run _radius_status_summary
    assert_output --partial "not sent (no scope enables one"
    store_scope_set lab vendor_attrs=cisco
    store_scope_set prod devices=10.1.2.3=wti,10.2.0.0/16=juniper
    run _radius_notes
    assert_line "vendors|1|4|2"
    run _radius_status_summary
    assert_output --partial "enabled for 1 of 4 scope(s), 2 tagged address(es)"
}

@test "conf: PAP only, own module instances, no proxy, no status server, nothing of the package included" {
    use_store store.radius.yaml
    render
    grep -q '^proxy_requests = no$' "${OUT}/conf"
    grep -q '^	status_server = no$' "${OUT}/conf"
    refute grep -q 'INCLUDE' "${OUT}/conf"
    refute grep -qi 'eap\|mschap\|chap ' "${OUT}/conf"
    run grep -cE '^\s(files|pap|always|detail|linelog) tacctl_' "${OUT}/conf"
    assert_output "6"
    # A reject carries none of the group's reply items.
    grep -qF '&Cisco-AVPair !* ANY' "${OUT}/conf"
    grep -qF '&Juniper-Local-User-Name !* ANY' "${OUT}/conf"
    grep -qF '&WTI-Super !* ANY' "${OUT}/conf"
    grep -qF '&Service-Type !* ANY' "${OUT}/conf"
}

@test "conf: command rules are not rendered" {
    use_store store.radius.yaml
    render
    refute grep -qi 'allow-commands\|deny-commands\|traceroute' "${OUT}/conf" "${OUT}/users"
}

# --- golden output, both layouts ---------------------------------------------

@test "golden: Debian/Ubuntu layout" {
    use_store store.radius.yaml
    render_as debian
    golden_diff "${OUT}/conf" radius.debian.conf
    golden_diff "${OUT}/users" radius.debian.users
    golden_diff "${OUT}/dictionary" radius.dictionary
    grep -q '^logdir = /var/log/freeradius$' "${OUT}/conf"
    grep -q '^pidfile = /run/freeradius/freeradius.pid$' "${OUT}/conf"
    grep -q '^libdir = /usr/lib/freeradius$' "${OUT}/conf"
    grep -q '^	user = freerad$' "${OUT}/conf"
}

@test "golden: RHEL-family layout" {
    use_store store.radius.yaml
    render_as rhel
    golden_diff "${OUT}/conf" radius.rhel.conf
    golden_diff "${OUT}/users" radius.rhel.users
    # The same dictionary: both families keep the package's main one in one place.
    golden_diff "${OUT}/dictionary" radius.dictionary
    grep -q '^logdir = /var/log/radius$' "${OUT}/conf"
    grep -q '^pidfile = /run/radiusd/radiusd.pid$' "${OUT}/conf"
    grep -q '^libdir = /usr/lib64/freeradius$' "${OUT}/conf"
    grep -q '^	user = radiusd$' "${OUT}/conf"
    grep -q '^	group = radiusd$' "${OUT}/conf"
}

@test "golden: the two layouts differ in the main settings only" {
    use_store store.radius.yaml
    render_as debian
    cp "${OUT}/conf" "${OUT}/debian.conf"
    render_as rhel
    run bash -c 'diff <(sed "/^server tacctl/,\$!d; /Tmp-String-0/d" "$1") <(sed "/^server tacctl/,\$!d; /Tmp-String-0/d" "$2")' _ "${OUT}/debian.conf" "${OUT}/conf"
    assert_success
}

# --- layout detection --------------------------------------------------------

layout_of() {
    (
        unset TACCTL_RADIUS_DIR TACCTL_RADIUS_LOG TACCTL_RADIUS_BIN TACCTL_RADIUS_DICT
        export TACCTL_RADIUS_FAMILY="$1"
        # shellcheck disable=SC1090
        source "$TACCTL_BIN_SCRIPT"
        backend_radius_describe
        echo "bin=${RADIUS_BIN}"
        echo "dict=${RADIUS_SYSTEM_DICT}"
        backend_radius_artifacts
    )
}

@test "layout: Debian/Ubuntu paths, unit, account and binary" {
    run layout_of debian
    assert_line "units=freeradius.service"
    assert_line "user=freerad"
    assert_line "config_dir=/etc/freeradius/3.0"
    assert_line "log_dir=/var/log/freeradius"
    assert_line "bin=/usr/sbin/freeradius"
    assert_line "/etc/freeradius/3.0/tacctl-radius.conf"
    assert_line "/etc/freeradius/3.0/tacctl-radius.users"
    assert_line "/etc/freeradius/3.0/tacctl-radius-dictionary/dictionary"
    assert_line "dict=/usr/share/freeradius/dictionary"
}

@test "layout: RHEL-family paths, unit, account and binary" {
    run layout_of rhel
    assert_line "units=radiusd.service"
    assert_line "user=radiusd"
    assert_line "config_dir=/etc/raddb"
    assert_line "log_dir=/var/log/radius"
    assert_line "bin=/usr/sbin/radiusd"
    assert_line "/etc/raddb/tacctl-radius.conf"
    assert_line "/etc/raddb/tacctl-radius-dictionary/dictionary"
    assert_line "dict=/usr/share/freeradius/dictionary"
}

@test "drop-in: Debian runs the daemon in the foreground under the package's unit, RHEL forks; both name tacctl's instance and dictionary" {
    local dropin_of='unset TACCTL_RADIUS_DIR TACCTL_RADIUS_LOG TACCTL_RADIUS_BIN; source "$1"; _radius_dropin_text'
    run env TACCTL_RADIUS_FAMILY=debian bash -s "$TACCTL_BIN_SCRIPT" <<< "$dropin_of"
    assert_line "ExecStartPre="
    assert_line "ExecStart="
    assert_line "ExecStartPre=/usr/sbin/freeradius -C -lstdout -d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius"
    assert_line "ExecStart=/usr/sbin/freeradius -f -d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius"
    assert_line "ExecReload=/usr/sbin/freeradius -C -lstdout -d /etc/freeradius/3.0 -D /etc/freeradius/3.0/tacctl-radius-dictionary -n tacctl-radius"
    run env TACCTL_RADIUS_FAMILY=rhel bash -s "$TACCTL_BIN_SCRIPT" <<< "$dropin_of"
    assert_line "ExecStartPre=-/bin/chown -R radiusd:radiusd /var/run/radiusd"
    assert_line "ExecStartPre=/usr/sbin/radiusd -C -lstdout -d /etc/raddb -D /etc/raddb/tacctl-radius-dictionary -n tacctl-radius"
    assert_line "ExecStart=/usr/sbin/radiusd -d /etc/raddb -D /etc/raddb/tacctl-radius-dictionary -n tacctl-radius"
    assert_line 'ExecReload=/bin/kill -HUP $MAINPID'
}

# --- notes -------------------------------------------------------------------

@test "notes: groups whose command rules restrict something and have RADIUS users are named" {
    use_store store.radius.yaml
    run _radius_notes
    # bob (operator) is served; readonly has only carol (disabled) and the sink.
    assert_line "commands|operator"
    run backend_radius_render_notes
    assert_output --partial "RADIUS does not enforce the command rules (commands.<group>) of: operator."
}

@test "notes: a group with a permit-everything rule set is not named" {
    use_store store.radius.yaml
    conf_set_json commands.operator '[{"name": "*", "action": "permit"}]'
    run _radius_notes
    refute_line --partial "commands|"
}

@test "notes: a secret beyond the interoperability advice is named by scope, never by value" {
    use_store store.radius.yaml
    run _radius_notes
    assert_line "secret|lab, prod-inner"
    refute_output --partial "quoted"
    assert_line "filters|4 allow, 2 deny"
}

# --- contract verbs that only read -------------------------------------------

@test "secret_constraints: the interoperability advice" {
    run backend_radius_secret_constraints
    assert_line "max_len=63"
    assert_line "charset=[!-~]"
}

@test "describe: no import command (a hand edit cannot be adopted)" {
    run backend_describe radius import_cmd
    assert_failure
    run backend_describe radius protocol
    assert_output "radius"
    run backend_describe radius impl
    assert_output "freeradius"
}

@test "installed: needs the daemon and something of tacctl's (drop-in or rendered config)" {
    run backend_radius_installed
    assert_failure
    mkdir -p "$(dirname "$TACCTL_RADIUS_BIN")" "$TACCTL_RADIUS_DIR"
    printf '#!/bin/sh\n' > "$TACCTL_RADIUS_BIN"; chmod +x "$TACCTL_RADIUS_BIN"
    # The package alone is not tacctl's install.
    run backend_radius_installed
    assert_failure
    : > "$RADIUS_CONF"
    backend_radius_installed
}

@test "device_vars: the ports of the built-in listeners and the scope's secret" {
    use_store store.radius.yaml
    run backend_radius_device_vars cisco prod
    assert_line "AUTH_PORT=1812"
    assert_line "ACCT_PORT=1813"
    assert_line "SECRET=prod-secret-0123456789abcdef"
    conf_set_json listeners.radius.auth '{"network": "udp", "address": "10.1.1.1:11812", "role": "auth"}'
    run backend_radius_device_vars juniper prod
    assert_line "AUTH_PORT=11812"
}

# --- listeners ---------------------------------------------------------------

@test "listeners: auth on udp :1812 and acct on udp :1813 without anything written" {
    run backend_radius_listeners list
    assert_output "$(printf 'auth udp :1812\nacct udp :1813')"
    run backend_listeners radius
    assert_line --index 0 "$(printf 'auth\tudp\t:1812\tauth\t-\tdefault')"
    assert_line --index 1 "$(printf 'acct\tudp\t:1813\tacct\t-\tdefault')"
}

@test "listeners: the schema takes udp and udp6 for radius, auth or acct, and refuses tcp and 'both'" {
    run conf_set_json listeners.radius.mgmt '{"network": "udp", "address": "10.1.0.1:1900"}'
    assert_success
    run backend_listeners radius
    assert_line --index 2 "$(printf 'mgmt\tudp\t10.1.0.1:1900\tauth\t-\toverride')"
    run conf_set_json listeners.radius.x '{"network": "tcp", "address": ":1812"}'
    assert_failure
    assert_output --partial "the radius backend listens on udp or udp6 only"
    run conf_set_json listeners.radius.x '{"network": "udp", "address": ":1900", "role": "both"}'
    assert_failure
    assert_output --partial "a radius listener has role acct or auth"
    run conf_set_json listeners.radius.x '{"network": "udp", "address": ":1900", "tls": {"enabled": true}}'
    assert_failure
    assert_output --partial "reserved"
}

@test "listeners: udp and udp6 on one port do not collide; two udp listeners on one port do; tcp 49 is unaffected" {
    run conf_set_json listeners.radius.auth6 '{"network": "udp6", "address": "[::]:1812"}'
    assert_success
    run conf_set_json listeners.radius.again '{"network": "udp", "address": "10.1.0.1:1812"}'
    assert_failure
    assert_output --partial "already used by listeners.radius.auth"
    # The TACACS+ listeners still collide across families, as they always did.
    run conf_set_json listeners.tacacs.six '{"network": "tcp6", "address": "[::]:49"}'
    assert_failure
    assert_output --partial "already used by listeners.tacacs.default"
}

@test "listeners: rendered as listen sections, IPv4 wildcard for udp and :: for udp6" {
    use_store store.radius.yaml
    conf_set_json listeners.radius.auth '{"network": "udp", "address": "10.1.1.1:11812", "role": "auth"}'
    conf_set_json listeners.radius.auth6 '{"network": "udp6", "address": "[::]:1812"}'
    render
    run grep -A5 'listeners.radius' "${OUT}/conf"
    assert_output "$(cat <<'EOF'
	# listeners.radius.auth
	listen {
		type = auth
		ipaddr = 10.1.1.1
		port = 11812
	}
	# listeners.radius.acct
	listen {
		type = acct
		ipaddr = *
		port = 1813
	}
	# listeners.radius.auth6
	listen {
		type = auth
		ipv6addr = ::
		port = 1812
	}
EOF
)"
}
