#!/usr/bin/env bats
# The RADIUS backend (lib/backends/radius.sh) through the commands, with the
# package manager, systemd, the daemon binary and ss stubbed: 'backend
# enable|disable radius' on both distro layouts, what a mutation renders,
# scope 'protocols' filtering, vendor attributes, drift, the daemon's config
# check, listeners, the status and log sections with two backends, the way
# from the release before the dictionary (upgrade, or the next mutation),
# and uninstall.
#
# The stubs keep state in $SD (which units are active, which are enabled) so
# that 'is-active' answers what the commands before it did. Knobs, files in
# $SD: 'fail-start' (a start or restart leaves the unit inactive),
# 'fail-check' (the daemon's -C rejects the config).
#
# What real FreeRADIUS does with the rendered files is not tested here: see
# "RADIUS in containers" in tests/README.md.
#
# Against the Go binary (tests/blackbox.list) the commands run the binary;
# the helpers that call bash functions (tc, enabled_list, pre_vendor_state)
# keep sourcing the bash library, and the module's lifecycle phases run
# through the hidden '_phase' command (upgrade_radius, radius_uninstall).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export SD="${BATS_TEST_TMPDIR}/sd"
    export TACCTL_SYSTEMD_DIR="${BATS_TEST_TMPDIR}/systemd"
    export TACCTL_OVERRIDE_DIR="${TACCTL_SYSTEMD_DIR}/tacquito.service.d"
    export TACCTL_SETTLE_SECONDS=0
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    mkdir -p "$SD" "$TACCTL_SYSTEMD_DIR" "$TACCTL_LOGROTATE_DIR" "$TMPDIR"
    # The bash library, whichever implementation the commands run.
    TACCTL_LIB="${TACCTL_SRC}/bin/tacctl.sh"
    STORE="${TACCTL_STATE_DIR}/store.yaml"
    RENDERED="${TACCTL_STATE_DIR}/rendered.json"
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
    RCONF="${TACCTL_RADIUS_DIR}/tacctl-radius.conf"
    RUSERS="${TACCTL_RADIUS_DIR}/tacctl-radius.users"
    RDICT="${TACCTL_RADIUS_DIR}/tacctl-radius-dictionary/dictionary"

    stub_cmd chown
    stub_cmd logger
    stub_cmd sleep
    stub_cmd journalctl
    stub_cmd curl 'exit 7'
    stub_cmd ps 'echo 2048'
    stub_cmd id 'exit 0'
    stub_cmd systemctl '
verb="$1"; shift
units=(); now=0
for a in "$@"; do
  case "$a" in
    --now) now=1 ;;
    -*) ;;
    *) units+=("${a%.service}") ;;
  esac
done
u="${units[0]:-}"
case "$verb" in
  is-active)  if [[ -e "$SD/active.$u" ]]; then echo active; exit 0; fi; echo inactive; exit 3 ;;
  is-enabled) if [[ -e "$SD/enabled.$u" ]]; then echo enabled; exit 0; fi; echo disabled; exit 1 ;;
  start|restart)
    if [[ -e "$SD/fail-start" ]]; then rm -f "$SD/active.$u"; exit 1; fi
    : > "$SD/active.$u" ;;
  stop)    rm -f "$SD/active.$u" ;;
  enable)  : > "$SD/enabled.$u"; (( now )) && : > "$SD/active.$u" ;;
  disable) rm -f "$SD/enabled.$u"; (( now )) && rm -f "$SD/active.$u" ;;
  show)
    case " $* " in
      *MainPID*) if [[ -e "$SD/active.$u" ]]; then echo MainPID=4242; else echo MainPID=0; fi ;;
      *) echo "ActiveEnterTimestamp=Fri 2026-10-02 10:00:00 UTC" ;;
    esac ;;
esac
exit 0'
    # udp: whatever unit is active listens on the default ports.
    stub_cmd ss 'case "$*" in
  *-u*) if [[ -e "$SD/active.freeradius" || -e "$SD/active.radiusd" ]]; then echo "UNCONN 0 0 0.0.0.0:1812 0.0.0.0:*"; echo "UNCONN 0 0 0.0.0.0:1813 0.0.0.0:*"; fi ;;
  *)    echo "LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))" ;;
esac'
    # The package managers install the "package": the daemon, its
    # directories, and (Debian) a unit that is started at once.
    local install_pkg='
mkdir -p "$(dirname "$TACCTL_RADIUS_BIN")" "$TACCTL_RADIUS_DIR" "$TACCTL_RADIUS_LOG"
cat > "$TACCTL_RADIUS_BIN" <<DAEMON
#!/usr/bin/env bash
echo "radiusd \$*" >> "$CALLS_LOG"
dir=""; name=""
while (( \$# )); do case "\$1" in -d) dir="\$2"; shift ;; -n) name="\$2"; shift ;; esac; shift; done
ls -la "\$dir" >> "$SD/check-dir.log" 2>&1
[[ -r "\$dir/\$name.conf" && -r "\$dir/\$name.users" ]] || { echo "Error: cannot read \$dir/\$name.conf"; exit 1; }
if [[ -e "$SD/fail-check" ]]; then echo "Fri Oct  2 10:00:00 2026 : Error: \$dir/\$name.conf[12]: Parse error"; exit 1; fi
exit 0
DAEMON
chmod +x "$TACCTL_RADIUS_BIN"'
    stub_cmd apt-get "case \" \$* \" in *\" install \"*) ${install_pkg}
: > \"\$SD/active.freeradius\"; : > \"\$SD/enabled.freeradius\" ;; esac"
    stub_cmd dnf "case \" \$* \" in *\" install \"*) ${install_pkg} ;; esac"
    export INSTALL_PKG="$install_pkg"

    # tacquito is installed and running; the store is the radius fixture.
    touch "${TACCTL_BIN}/tacquito" "${TACCTL_SYSTEMD_DIR}/tacquito.service"
    chmod +x "${TACCTL_BIN}/tacquito"
    : > "${SD}/active.tacquito"
    load_store_fixture store.radius.yaml
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
    : > "$CALLS_LOG"
}

# The CLI, colours stripped.
tacctl() {
    run "$TACCTL_BIN_SCRIPT" "$@"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# A function of the library under the script's own options.
tc() {
    run bash -c 'set -euo pipefail; source "$1"; shift; "$@"' _ "$TACCTL_LIB" "$@"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# The package is on the machine already (binary and directories), no unit state.
package_present() {
    bash -c "$INSTALL_PKG"
}

radius_up() {
    tacctl backend enable radius -y
    assert_success
    : > "$CALLS_LOG"
}

state() {
    local f
    for f in "$STORE" "$OVERRIDES" "$TACCTL_CONFIG" "$RCONF" "$RUSERS" "$RDICT" "$RENDERED"; do
        if [[ -f "$f" ]]; then
            echo "$(basename "$f") $(sha256sum < "$f")"
        else
            echo "$(basename "$f") absent"
        fi
    done
}

no_leftovers() {
    [[ -z "$(find "$TMPDIR" -mindepth 1 -maxdepth 1)" ]]
    [[ -z "$(find "$TACCTL_STATE_DIR" -maxdepth 1 \( -name '.apply.*' -o -name '.enable.*' -o -name '.radius-listen.*' \))" ]]
    [[ -z "$(find "$TACCTL_RADIUS_DIR" -name '.tacctl-check.*' -o -name '*.tacctl-new' 2> /dev/null)" ]]
}

enabled_list() {
    bash -c 'source "$1"; backends_enabled' _ "$TACCTL_LIB" | paste -sd' '
}

# --- enable ------------------------------------------------------------------

@test "enable (Debian layout): installs the packages, stops the package's own unit, renders, installs the drop-in, starts" {
    tacctl backend enable radius -y
    assert_success
    assert_output --partial "Installing FreeRADIUS (freeradius freeradius-utils)"
    assert_output --partial "Backend 'radius' is enabled and running."
    stub_called '^apt-get install -y -qq freeradius freeradius-utils$'
    # The unit the package started is stopped before anything of tacctl's exists.
    stub_called '^systemctl disable --quiet --now freeradius.service$'
    [[ "$(enabled_list)" == "tacacs radius" ]]

    # The three artifacts, recorded, 0640; the dictionary's directory 0750.
    [[ -f "$RCONF" && -f "$RUSERS" && -f "$RDICT" ]]
    [[ "$(stat -c %a "$RCONF")" == "640" && "$(stat -c %a "$RUSERS")" == "640" && "$(stat -c %a "$RDICT")" == "640" ]]
    [[ "$(stat -c %a "${RDICT%/*}")" == "750" ]]
    # The owner is set by 'chown' in bash, natively by the Go binary
    # (docs/plans/go-rewrite.md 3.9 item 2; internal/backend/radius checks
    # what it asks for): modes and content are the effect asserted for both.
    if [[ "$TACCTL_IMPL" == bash ]]; then
        stub_called "^chown root:freerad ${RCONF}.tacctl-new$"
        stub_called "^chown root:freerad ${RUSERS}.tacctl-new$"
        stub_called "^chown root:freerad ${RDICT}.tacctl-new$"
        stub_called "^chown root:freerad ${RDICT%/*}$"
    fi
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    grep -q "\"${RCONF}\"" "$RENDERED"
    grep -q "\"${RUSERS}\"" "$RENDERED"
    grep -q "\"${RDICT}\"" "$RENDERED"
    grep -q '^	user = freerad$' "$RCONF"
    grep -q "^\\\$INCLUDE ${TACCTL_RADIUS_DICT}$" "$RDICT"

    # The daemon's own check ran on a copy beside the live files, readable by
    # the service account's group, with the copy of the dictionary, and the
    # copy is gone.
    stub_called "^radiusd -C -lstdout -d ${TACCTL_RADIUS_DIR}/.tacctl-check\.[A-Za-z0-9]+ -D ${TACCTL_RADIUS_DIR}/.tacctl-check\.[A-Za-z0-9]+/dictionary.d -n tacctl-radius$"
    grep -q 'tacctl-radius.conf' "${SD}/check-dir.log"
    grep -q '^-rw-r----- .* tacctl-radius.users$' "${SD}/check-dir.log"
    grep -q '^drwxr-x--- .* \.$' "${SD}/check-dir.log"

    # The drop-in, then enable and start, in that order.
    local dropin="${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf"
    grep -q "^ExecStart=${TACCTL_RADIUS_BIN} -f -d ${TACCTL_RADIUS_DIR} -D ${RDICT%/*} -n tacctl-radius$" "$dropin"
    run grep -nE '^systemctl (daemon-reload|enable --quiet freeradius.service|start freeradius.service)$' "$CALLS_LOG"
    assert_line --index 0 --partial "daemon-reload"
    assert_line --index 1 --partial "enable --quiet freeradius.service"
    assert_line --index 2 --partial "start freeradius.service"
    [[ -e "${SD}/active.freeradius" && -e "${SD}/enabled.freeradius" ]]

    # The logrotate file names the three logs and the service account.
    grep -q "${TACCTL_RADIUS_LOG}/tacctl-auth.log" "${TACCTL_LOGROTATE_DIR}/tacctl-radius"
    grep -q '^	su freerad freerad$' "${TACCTL_LOGROTATE_DIR}/tacctl-radius"
    no_leftovers
}

@test "enable (RHEL layout): dnf, radiusd.service, the radiusd account, a forking ExecStart" {
    export TACCTL_RADIUS_FAMILY=rhel
    rm -f "${STUB_BIN}/apt-get"
    tacctl backend enable radius -y
    assert_success
    stub_called '^dnf install -y -q freeradius freeradius-utils$'
    local dropin="${TACCTL_SYSTEMD_DIR}/radiusd.service.d/tacctl.conf"
    grep -q "^ExecStart=${TACCTL_RADIUS_BIN} -d ${TACCTL_RADIUS_DIR} -D ${RDICT%/*} -n tacctl-radius$" "$dropin"
    grep -q '^ExecStartPre=-/bin/chown -R radiusd:radiusd /var/run/radiusd$' "$dropin"
    stub_called '^systemctl enable --quiet radiusd.service$'
    stub_called '^systemctl start radiusd.service$'
    if [[ "$TACCTL_IMPL" == bash ]]; then
        stub_called "^chown root:radiusd ${RCONF}.tacctl-new$"
    fi
    grep -q '^	user = radiusd$' "$RCONF"
    grep -q '^libdir = /usr/lib64/freeradius$' "$RCONF"
    grep -q '^pidfile = /run/radiusd/radiusd.pid$' "$RCONF"
    tacctl backend status radius
    assert_output --partial "installed, enabled"
    assert_output --partial "Listener auth: udp :1812 — unit active, listening on 0.0.0.0:1812"
}

@test "enable: the warnings of the rendered state are shown (command rules, secrets)" {
    tacctl backend enable radius -y
    assert_success
    assert_output --partial "RADIUS does not enforce the command rules (commands.<group>) of: operator."
    assert_output --partial "The secret of scope lab, prod-inner is longer than 63 characters or has a space"
    assert_output --partial "Over RADIUS no vendor attribute is sent to the devices of scope(s) lab, prod, prod-inner, wifi: an Access-Accept carries Service-Type only."
}

@test "enable: a FreeRADIUS that is already running is somebody's, and is neither taken nor stopped" {
    package_present
    : > "${SD}/active.freeradius"
    local before
    before=$(state)
    tacctl backend enable radius -y
    assert_failure
    assert_output --partial "freeradius.service is running: somebody's RADIUS server"
    assert_output --partial "systemctl disable --now freeradius.service"
    [[ "$(state)" == "$before" ]]
    [[ -e "${SD}/active.freeradius" ]]
    ! stub_called '^systemctl (stop|disable|restart|start) .*freeradius'
    ! stub_called '^apt-get'
    [[ ! -e "${TACCTL_SYSTEMD_DIR}/freeradius.service.d" ]]
    no_leftovers
}

@test "enable: so is one that is only enabled at boot; once handed over, enable goes through without the package manager" {
    package_present
    : > "${SD}/enabled.freeradius"
    tacctl backend enable radius -y
    assert_failure
    assert_output --partial "freeradius.service is enabled at boot"
    rm -f "${SD}/enabled.freeradius"
    tacctl backend enable radius -y
    assert_success
    assert_output --partial "FreeRADIUS is already installed"
    ! stub_called '^apt-get'
}

@test "enable: a config the daemon rejects is not installed; nothing is changed" {
    package_present
    : > "${SD}/fail-check"
    local before
    before=$(state)
    tacctl backend enable radius -y
    assert_failure
    assert_output --partial "FreeRADIUS rejects the rendered configuration"
    # The daemon's message names the live path, not the scratch copy.
    assert_output --partial "${RCONF}[12]: Parse error"
    assert_output --partial "Backend 'radius' was not enabled."
    [[ "$(state)" == "$before" ]]
    [[ ! -e "$RCONF" && ! -e "$RUSERS" ]]
    ! stub_called '^systemctl (start|enable) .*freeradius'
    no_leftovers
}

@test "enable: a daemon that does not come up is undone: artifacts, tacctl.yaml and the drop-in are as before" {
    : > "${SD}/fail-start"
    local before
    before=$(state)
    tacctl backend enable radius -y
    assert_failure
    assert_output --partial "FreeRADIUS failed to start"
    assert_output --partial "Backend 'radius' was not enabled."
    [[ "$(state)" == "$before" ]]
    [[ ! -e "${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf" ]]
    [[ ! -e "${SD}/enabled.freeradius" ]]
    no_leftovers
}

# --- disable -----------------------------------------------------------------

@test "disable: stops and disables the unit, removes the drop-in, keeps the rendered files; enable brings it back without installing" {
    radius_up
    tacctl backend disable radius -y
    assert_success
    assert_output --partial "Backend 'radius' is disabled"
    [[ "$(enabled_list)" == "tacacs" ]]
    stub_called '^systemctl stop freeradius.service$'
    stub_called '^systemctl disable --quiet freeradius.service$'
    [[ ! -e "${SD}/active.freeradius" && ! -e "${SD}/enabled.freeradius" ]]
    [[ ! -e "${TACCTL_SYSTEMD_DIR}/freeradius.service.d" ]]
    [[ -f "$RCONF" && -f "$RUSERS" ]]
    tacctl backend list
    assert_line --regexp '^  radius +radius +freeradius +yes +no +inactive'

    : > "$CALLS_LOG"
    tacctl backend enable radius -y
    assert_success
    refute_output --partial "is not installed"
    ! stub_called '^apt-get'
    [[ -f "${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf" ]]
    [[ -e "${SD}/active.freeradius" && -e "${SD}/enabled.freeradius" ]]
}

@test "disable: while disabled its artifacts are not rendered, and the store can change" {
    radius_up
    tacctl backend disable radius -y
    local before
    before=$(sha256sum < "$RUSERS")
    tacctl user disable bob
    assert_success
    [[ "$(sha256sum < "$RUSERS")" == "$before" ]]
    # Enabling renders the current store.
    tacctl backend enable radius -y
    assert_success
    refute grep -q '^bob' "$RUSERS"
}

@test "re-enable: refused while somebody runs the package's configuration under the unit, which is left running" {
    radius_up
    tacctl backend disable radius -y
    : > "${SD}/active.freeradius"
    : > "$CALLS_LOG"
    tacctl backend enable radius -y
    assert_failure
    assert_output --partial "somebody's RADIUS server"
    [[ -e "${SD}/active.freeradius" ]]
    ! stub_called '^systemctl (stop|disable) .*freeradius'
    [[ "$(enabled_list)" == "tacacs" ]]
}

# --- what a mutation renders -------------------------------------------------

@test "mutation: both backends are rendered and restarted; the users file follows the store" {
    radius_up
    grep -q '^bob' "$RUSERS"
    tacctl user disable bob
    assert_success
    refute grep -q '^bob' "$RUSERS"
    stub_called '^systemctl restart tacquito$'
    stub_called '^systemctl restart freeradius.service$'
    # The check ran on the new render.
    stub_called '^radiusd -C '
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    no_leftovers
}

@test "mutation: a change RADIUS does not see (a TACACS+-only scope's secret) restarts tacquito only" {
    radius_up
    tacctl scope secret legacy set "another-legacy-secret-0123456789"
    assert_success
    stub_called '^systemctl restart tacquito$'
    ! stub_called '^systemctl restart freeradius'
}

@test "mutation: a render the daemon rejects changes nothing, in either backend" {
    radius_up
    : > "${SD}/fail-check"
    local before
    before=$(state)
    tacctl user disable bob
    assert_failure
    assert_output --partial "FreeRADIUS rejects the rendered configuration"
    [[ "$(state)" == "$before" ]]
    ! stub_called '^systemctl restart'
    no_leftovers
}

@test "mutation: a secret FreeRADIUS cannot carry is refused and the store keeps the old one" {
    radius_up
    local before
    before=$(state)
    tacctl scope secret prod set 'back\slash-and-$dollar-0123456789'
    assert_failure
    assert_output --partial "scope 'prod': its secret holds both a backslash and a dollar sign"
    [[ "$(state)" == "$before" ]]
}

@test "scope protocols: taking radius off a scope removes its clients and its users' entries; putting it back restores them" {
    radius_up
    grep -q 'tacctl_scope = "lab"' "$RCONF"
    tacctl scope protocols lab set tacacs
    assert_success
    refute grep -q 'tacctl_scope = "lab"' "$RCONF"
    refute grep -q '/lab"' "$RUSERS"
    refute grep -q '^bob' "$RUSERS"
    grep -q '^alice' "$RUSERS"
    tacctl scope protocols lab clear
    assert_success
    grep -q 'tacctl_scope = "lab"' "$RCONF"
    grep -q '^bob' "$RUSERS"
    # A RADIUS-only scope is in the RADIUS files and not in tacquito.yaml.
    grep -q 'tacctl_scope = "wifi"' "$RCONF"
    refute grep -q 'wifi-radius-only' "$TACCTL_CONFIG"
}

@test "rendered: disabled users and the sink are absent; overlapping prefixes are ordered most specific first" {
    radius_up
    refute grep -q '^carol' "$RUSERS"
    refute grep -q '^root' "$RUSERS"
    local inner outer
    inner=$(grep -n 'ipaddr = 10.10.99.0/24' "$RCONF" | cut -d: -f1)
    outer=$(grep -n 'ipaddr = 10.0.0.0/8' "$RCONF" | cut -d: -f1)
    (( inner < outer ))
}

# --- drift -------------------------------------------------------------------

@test "drift: a hand edit of either RADIUS file refuses mutations (exit 3) until 'config render --force', which keeps a copy" {
    radius_up
    echo "# hand edit" >> "$RUSERS"
    local before
    before=$(state)
    tacctl user disable bob
    assert_failure 3
    assert_output --partial "${RUSERS} was edited since tacctl rendered it"
    assert_output --partial "no way to adopt an edit of the RADIUS files"
    [[ "$(state)" == "$before" ]]

    tacctl config validate
    assert_failure
    assert_output --partial "DRIFT:"
    assert_output --partial "${RUSERS} — edited since tacctl rendered it"
    assert_output --partial "there is no way to adopt them into the store"

    tacctl config render
    assert_failure 3
    tacctl config render --force
    assert_success
    refute grep -q 'hand edit' "$RUSERS"
    run bash -c 'ls "$1"/backups/legacy/tacctl-radius.users.drift.*' _ "$TACCTL_STATE_DIR"
    assert_success
    grep -q 'hand edit' "${lines[0]}"
    tacctl user disable bob
    assert_success
}

@test "drift: a file tacctl has no record of is refused too, and replaced only with --force" {
    radius_up
    printf '{}\n' > "$RENDERED"
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null 2>&1
    python3 - "$RENDERED" "$RCONF" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); d.pop(sys.argv[2]); json.dump(d, open(sys.argv[1], 'w'))
PY
    echo "# not ours" >> "$RCONF"
    tacctl user disable bob
    assert_failure 3
    assert_output --partial "${RCONF} was not rendered by tacctl"
}

@test "validate: a missing artifact is reported for radius, and 'config render' puts it back" {
    radius_up
    rm -f "$RUSERS"
    tacctl config validate
    assert_failure
    assert_output --partial "Backend radius:"
    tacctl config render
    assert_success
    [[ -f "$RUSERS" ]]
    tacctl config validate
    assert_success
}

# --- listeners ---------------------------------------------------------------

@test "config listen --backend radius: shows both built-in listeners" {
    tacctl config listen --backend radius
    assert_success
    assert_output --partial "RADIUS listener 'auth' (auth): udp :1812   (built-in default)"
    assert_output --partial "RADIUS listener 'acct' (acct): udp :1813   (built-in default)"
    assert_output --partial "tacctl config listen --backend radius --listener <name> <network> <address>"
    refute_output --partial "tcp6"
}

@test "config listen --backend radius: a change is written, rendered into a listen section, and the unit restarted" {
    radius_up
    tacctl config listen --backend radius --listener auth udp 10.1.1.1:11812
    assert_success
    assert_output --partial "RADIUS listener 'auth' changed to udp 10.1.1.1:11812."
    run grep -A4 'listeners.radius.auth$' "$RCONF"
    assert_line --index 2 "		type = auth"
    assert_line --index 3 "		ipaddr = 10.1.1.1"
    assert_line --index 4 "		port = 11812"
    grep -q '10.1.1.1:11812' "$OVERRIDES"
    stub_called '^systemctl restart freeradius.service$'
    ! stub_called '^systemctl restart tacquito$'
    # The accounting listener keeps its role when moved.
    tacctl config listen --backend radius --listener acct udp :11813
    assert_success
    run grep -A4 'listeners.radius.acct$' "$RCONF"
    assert_line --index 2 "		type = acct"
    assert_line --index 4 "		port = 11813"
    # reset puts a built-in one back, and removes any other.
    tacctl config listen --backend radius --listener auth reset
    assert_success
    assert_output --partial "back on its default"
    tacctl config listen --backend radius --listener auth6 udp6 '[::]:1812'
    assert_success
    assert_output --partial "RADIUS listener 'auth6' (auth) added on udp6 [::]:1812."
    grep -q 'ipv6addr = ::$' "$RCONF"
    tacctl config listen --backend radius --listener auth6 reset
    assert_success
    assert_output --partial "RADIUS listener 'auth6' removed."
    refute grep -q 'ipv6addr = ::$' "$RCONF"
    no_leftovers
}

@test "config listen --backend radius: tcp, a taken port and a missing listener name are refused before anything is written" {
    radius_up
    local before
    before=$(state)
    tacctl config listen --backend radius --listener auth tcp :1812
    assert_failure
    assert_output --partial "the RADIUS backend listens on udp or udp6"
    tacctl config listen --backend radius --listener auth udp :1813
    assert_failure
    assert_output --partial "already used by listeners.radius.acct"
    tacctl config listen --backend radius udp :1900
    assert_failure
    assert_output --partial "--listener auth"
    [[ "$(state)" == "$before" ]]
}

@test "config listen --backend radius: a daemon that does not stay up gets the previous listener back" {
    radius_up
    local before
    before=$(state)
    : > "${SD}/fail-start"
    tacctl config listen --backend radius --listener auth udp 192.0.2.99:1812
    assert_failure
    assert_output --partial "did not stay up with the new listener"
    [[ "$(sha256sum < "$RCONF")" == "$(grep '^tacctl-radius.conf' <<< "$before" | cut -d' ' -f2-)" ]]
    refute grep -q '192.0.2.99' "$RCONF"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    no_leftovers
}

@test "config listen without --backend is still the TACACS+ default listener" {
    tacctl config listen
    assert_success
    assert_output --partial "Current listener: tcp :49"
}

# --- status and logs with two backends ---------------------------------------

plant_logs() {
    local now old
    now=$(date '+%Y-%m-%d %H:%M:%S')
    old=$(date -d '3 days ago' '+%Y-%m-%d %H:%M:%S')
    mkdir -p "$TACCTL_RADIUS_LOG"
    cat > "${TACCTL_RADIUS_LOG}/tacctl-auth.log" <<EOF
${old} Access-Reject scope=lab client=172.16.0.9 nas=sw9 reason='not an enabled user of this scope' user=mallory
${old} Access-Accept scope=lab client=172.16.0.9 nas=sw9 reason='-' user=alice
${now} Access-Accept scope=prod client=10.1.2.3 nas=core1 reason='-' user=alice
${now} Access-Reject scope=lab client=172.16.0.9 nas=sw9 reason='tacctl_pap: Crypt digest does not match "known good" digest' user=bob
${now} Access-Reject scope=prod client=10.1.2.3 nas=core1 reason='not an enabled user of this scope' user=alice bob
EOF
    cat > "${TACCTL_RADIUS_LOG}/tacctl-accounting.log" <<'EOF'
Fri Oct  2 10:00:00 2026
	User-Name = "alice"
	Acct-Status-Type = Start
	Acct-Session-Id = "s1"

Fri Oct  2 10:05:00 2026
	User-Name = "alice"
	Acct-Status-Type = Stop
	Acct-Session-Id = "s1"

EOF
    printf 'Fri Oct  2 10:00:00 2026 : Info: Ready to process requests\n' > "${TACCTL_RADIUS_LOG}/tacctl-radius.log"
    LOG_NOW="$now"
}

@test "status: each backend has its section; the RADIUS one shows service, listeners, notes, accounting and counts" {
    radius_up
    plant_logs
    tacctl status
    assert_success
    assert_output --partial "== Backend: tacacs (tacacs, tacquito) =="
    assert_output --partial "== Backend: radius (radius, freeradius) =="
    assert_output --partial "Service:              active (freeradius.service)"
    assert_output --partial "Listening (auth):     0.0.0.0:1812/udp"
    assert_output --partial "Listening (acct):     0.0.0.0:1813/udp"
    assert_output --partial "Config:               ${RCONF}"
    assert_output --partial "Authentication:       PAP against the store's bcrypt hashes"
    assert_output --partial "Command rules:        not enforced over RADIUS (commands.<group> of: operator)"
    assert_output --partial "Connection filters:   enforced (4 allow, 2 deny)"
    assert_output --partial "(2 records)"
    assert_output --partial "Accepted:           1"
    assert_output --partial "Rejected:           2"
    # The radius section comes after the tacacs one, and holds its own lines.
    local t r l
    t=$(grep -n 'Backend: tacacs' <<< "$output" | cut -d: -f1)
    r=$(grep -n 'Backend: radius' <<< "$output" | cut -d: -f1)
    l=$(grep -n 'Listening (auth)' <<< "$output" | cut -d: -f1)
    (( t < r && r < l ))
}

@test "status: a stopped RADIUS daemon is shown as such" {
    radius_up
    rm -f "${SD}/active.freeradius"
    tacctl status
    assert_output --partial "Service:              inactive (freeradius.service)"
    assert_output --partial "port 1812/udp not detected"
}

@test "log: --backend radius shows the auth log and the daemon log; failures are the last day's rejects" {
    radius_up
    plant_logs
    tacctl log tail 2 --backend radius
    assert_success
    assert_output --partial "Recent RADIUS Authentications"
    assert_line --partial "user=alice bob"
    refute_output --partial "user=mallory"
    assert_output --partial "Ready to process requests"

    tacctl log failures --backend radius
    assert_line --partial "Crypt digest does not match"
    refute_output --partial "user=mallory"
    refute_output --partial "Access-Accept"

    tacctl log search mallory --backend radius
    assert_line --partial "user=mallory"

    tacctl log accounting 1 --backend radius
    assert_output --partial "Acct-Status-Type = Stop"
    refute_output --partial "Acct-Status-Type = Start"

    # Without --backend both backends report, each under its heading.
    tacctl log tail 1
    assert_output --partial "== Backend: tacacs (tacacs, tacquito) =="
    assert_output --partial "== Backend: radius (radius, freeradius) =="
}

@test "log clear --backend radius: truncates the three logs after a yes" {
    radius_up
    plant_logs
    tacctl log clear --backend radius -y
    assert_success
    [[ ! -s "${TACCTL_RADIUS_LOG}/tacctl-auth.log" && ! -s "${TACCTL_RADIUS_LOG}/tacctl-accounting.log" && ! -s "${TACCTL_RADIUS_LOG}/tacctl-radius.log" ]]
}

# bats test_tags=bash-only
@test "last login: the newest Access-Accept of exactly that user; a longer name ending the same does not count" {
    radius_up
    plant_logs
    tc backend_radius_last_login alice
    assert_output "$LOG_NOW"
    # 'user=alice bob' was rejected, and is neither alice's nor bob's login.
    tc backend_radius_last_login bob
    assert_output "never"
    tc backends_last_login alice
    assert_output "$LOG_NOW"
}

@test "config show: lists the RADIUS backend's config file and listeners" {
    radius_up
    tacctl config show
    assert_success
    assert_output --partial "$RCONF"
    assert_output --partial "1812"
}

# --- upgrade, uninstall ------------------------------------------------------

# The state the release before the dictionary leaves: its two files (a real
# render of that release, recorded as what tacctl rendered), no dictionary,
# and its drop-in, which starts the daemon without -D.
pre_vendor_state() {
    local dropin="${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf"
    cp "${TACCTL_SRC}/tests/fixtures/radius.pre-vendor.conf" "$RCONF"
    cp "${TACCTL_SRC}/tests/fixtures/radius.pre-vendor.users" "$RUSERS"
    rm -rf "${RDICT%/*}"
    tc rendered_record "$RCONF"
    tc rendered_record "$RUSERS"
    tc rendered_forget "$RDICT"
    cat > "$dropin" <<EOF
# Installed by tacctl ('tacctl backend enable radius'), removed by 'tacctl backend disable radius'.
[Service]
ExecStartPre=
ExecStartPre=${TACCTL_RADIUS_BIN} -C -lstdout -d ${TACCTL_RADIUS_DIR} -n tacctl-radius
ExecStart=
ExecStart=${TACCTL_RADIUS_BIN} -f -d ${TACCTL_RADIUS_DIR} -n tacctl-radius
EOF
    : > "$CALLS_LOG"
}

# The upgrade phases of this backend, then the closing summary lines
# ('SUMMARY <note>', as '_phase' prints them).
upgrade_radius() {
    if [[ "$TACCTL_IMPL" == go ]]; then
        run "$TACCTL_BIN_SCRIPT" _phase radius upgrade config,files,finish /nonexistent
    else
        run bash -c 'set -euo pipefail; source "$1"; for p in config files finish; do backend_radius_upgrade "$p" /nonexistent; done
                     printf "SUMMARY %s\n" ${UPGRADE_SUMMARY_NOTES[@]+"${UPGRADE_SUMMARY_NOTES[@]}"}' _ "$TACCTL_LIB"
    fi
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

# One uninstall phase of this backend.
radius_uninstall() {
    if [[ "$TACCTL_IMPL" == go ]]; then
        run "$TACCTL_BIN_SCRIPT" _phase radius uninstall "$@"
        output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
        mapfile -t lines <<< "$output"
    else
        tc backend_radius_uninstall "$@"
    fi
}

@test "upgrade: an install from the release before the dictionary is re-rendered, not taken for drift; the drop-in gains -D, then one restart" {
    radius_up
    pre_vendor_state
    local dropin="${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf"
    run "$TACCTL_BIN_SCRIPT" config validate
    refute_output --partial "DRIFT"
    upgrade_radius
    assert_success
    assert_output --partial "RADIUS: re-rendered ${RCONF}, ${RUSERS}, ${RDICT}."
    assert_output --partial "RADIUS: no scope enables a vendor attribute, so an Access-Accept carries Service-Type only."
    assert_output --partial "RADIUS: updated ${dropin}."
    assert_line "SUMMARY RADIUS: config re-rendered for this release, FreeRADIUS restarted"
    [[ -f "$RDICT" ]]
    grep -q "\"${RDICT}\"" "$RENDERED"
    grep -q "^ExecStart=${TACCTL_RADIUS_BIN} -f -d ${TACCTL_RADIUS_DIR} -D ${RDICT%/*} -n tacctl-radius$" "$dropin"
    ! grep -q 'Cisco-AVPair = ' "$RUSERS"
    # Artifacts, then the drop-in (daemon-reload), then exactly one restart.
    run grep -nE '^systemctl (daemon-reload|restart freeradius.service)$' "$CALLS_LOG"
    assert_line --index 0 --partial "daemon-reload"
    assert_line --index 1 --partial "restart freeradius.service"
    [[ "${#lines[@]}" == 2 ]]
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"
    no_leftovers
}

@test "upgrade: nothing to do when the artifacts and the drop-in are current (no restart, no summary line)" {
    radius_up
    upgrade_radius
    assert_success
    refute_output --partial "re-rendered"
    refute_line --partial "SUMMARY RADIUS"
    ! stub_called '^systemctl restart freeradius'
}

@test "upgrade: a hand-edited artifact is not replaced, and neither the drop-in nor the daemon is touched" {
    radius_up
    pre_vendor_state
    echo "# hand edit" >> "$RUSERS"
    local dropin="${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf" before
    before=$(state; cat "$dropin")
    upgrade_radius
    assert_success
    assert_output --partial "was edited since tacctl rendered it"
    assert_output --partial "The RADIUS files were not re-rendered; FreeRADIUS keeps serving the previous ones."
    assert_line --partial "SUMMARY RADIUS: NOT brought in line with this release"
    [[ "$(state; cat "$dropin")" == "$before" ]]
    ! stub_called '^systemctl (restart|daemon-reload)'
}

# cmd_upgrade itself, with what shells out to git, go, apt and fixed system
# paths replaced: the build is one line, there is no management repo to
# pull. The RADIUS re-render runs in the 'config' phase, which comes after
# the build and the scripts pull (and so after a self-update's re-exec): its
# lines must follow the banner and the build, and precede the system files
# and the summary. Against bash the TACACS+ phases are overridden functions;
# against Go the binary's real TACACS+ phases run with tacctl's fixed host
# paths under TACCTL_TEST_ROOT (a -tags testknobs build): Go there, a
# tacquito checkout that is current, a deploy directory with no clone.
@test "upgrade: the output reads in order; the RADIUS re-render and restart come after the banner and the build" {
    radius_up
    pre_vendor_state
    mkdir -p "${BATS_TEST_TMPDIR}/deploy/bin"
    : > "${BATS_TEST_TMPDIR}/deploy/bin/tacctl.sh"
    stub_cmd ln
    if [[ "$TACCTL_IMPL" == go ]]; then
        local root="${BATS_TEST_TMPDIR}/hostroot"
        mkdir -p "${root}/opt/tacctl/bin" "${root}/usr/local/go/bin" "${BATS_TEST_TMPDIR}/tacquito-src"
        : > "${root}/opt/tacctl/bin/tacctl.sh"
        printf '#!/bin/sh\n' > "${root}/usr/local/go/bin/go"
        chmod 755 "${root}/usr/local/go/bin/go"
        printf '#!/bin/sh\n' > "${TACCTL_BIN}/tacquito"
        stub_cmd git 'case "$*" in *"rev-parse --short HEAD"*) echo abc1234 ;; *"rev-parse"*) echo abc1234abc1234 ;; esac'
        stub_cmd dpkg-query 'echo "install ok installed"'
        stub_cmd apt-get
        run env TACCTL_TEST_ROOT="$root" TACQUITO_SRC="${BATS_TEST_TMPDIR}/tacquito-src" "$TACCTL_BIN_SCRIPT" upgrade
        ! stub_called '^(apt-get|ln) ' || { stub_calls; return 1; }
        [[ ! -e "${root}/usr/local/bin/tacctl" ]]
    else
        stub_cmd git
        run bash -c 'set -euo pipefail; source "$1"
            DEPLOY_DIR="$2"
            _tacacs_upgrade_preflight() { :; }
            _tacacs_upgrade_build() { info "Current commit: abc1234"; SKIP_BUILD=true; CURRENT_COMMIT=abc1234; NEW_COMMIT=abc1234; }
            _tacacs_upgrade_files() { :; }
            _tacacs_upgrade_finish() { UPGRADE_SUMMARY_HEAD="Scripts Updated"; }
            ensure_dependencies() { :; }
            ensure_safe_directory() { :; }
            install_man_page() { :; }
            update_if_changed() { :; }
            cmd_upgrade' _ "$TACCTL_LIB" "${BATS_TEST_TMPDIR}/deploy"
    fi
    assert_success
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    local order=() pattern n
    for pattern in "tacctl Upgrade" "Backends: tacacs (tacquito), radius (freeradius)" \
                   "Current commit: abc1234" "RADIUS: re-rendered " "Restarting freeradius" \
                   "FreeRADIUS is running." "Updating system files" "Scripts Updated"; do
        n=$(grep -nF -- "$pattern" <<< "$output" | head -1 | cut -d: -f1)
        [[ -n "$n" ]] || { echo "missing: ${pattern}"; echo "$output"; return 1; }
        order+=("$n")
    done
    # Each line after the one before it.
    for n in 1 2 3 4 5 6 7; do
        (( order[n] > order[n - 1] )) || { echo "out of order at: ${order[*]}"; echo "$output"; return 1; }
    done
    # The banner is printed once, and nothing comes before it.
    [[ "$(grep -c 'tacctl Upgrade' <<< "$output")" == 1 ]]
    [[ -z "$(head -n "$(( order[0] - 2 ))" <<< "$output" | tr -d '[:space:]')" ]]
}

@test "upgrade: a disabled backend (no drop-in) is left alone" {
    radius_up
    tacctl backend disable radius -y
    : > "$CALLS_LOG"
    local before
    before=$(state)
    upgrade_radius
    assert_success
    [[ "$(state)" == "$before" ]]
    [[ ! -e "${TACCTL_SYSTEMD_DIR}/freeradius.service.d" ]]
    ! stub_called '^systemctl'
}

@test "the next mutation after the code changed: all three rendered, the drop-in brought in line before the restart" {
    radius_up
    pre_vendor_state
    local dropin="${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf"
    tacctl user disable bob
    assert_success
    refute_output --partial "edited since"
    [[ -f "$RDICT" ]]
    grep -q "\"${RDICT}\"" "$RENDERED"
    grep -q -- "-D ${RDICT%/*} -n tacctl-radius$" "$dropin"
    run grep -nE '^systemctl (daemon-reload|restart freeradius.service)$' "$CALLS_LOG"
    assert_line --index 0 --partial "daemon-reload"
    assert_line --index 1 --partial "restart freeradius.service"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"
}

@test "dictionary: a hand edit of it refuses mutations like the other two; a missing package dictionary fails clearly and changes nothing" {
    radius_up
    echo "ATTRIBUTE X 3000 string" >> "$RDICT"
    tacctl user disable bob
    [[ "$status" == 3 ]]
    assert_output --partial "${RDICT} was edited since tacctl rendered it"
    tacctl config render --force
    assert_success
    ! grep -q 'ATTRIBUTE X' "$RDICT"
    ls "${TACCTL_STATE_DIR}/backups/legacy/dictionary.drift."* > /dev/null

    rm -f "$TACCTL_RADIUS_DICT"
    local before
    before=$(state)
    tacctl user disable bob
    assert_failure
    assert_output --partial "FreeRADIUS's main dictionary is not at ${TACCTL_RADIUS_DICT}"
    [[ "$(state)" == "$before" ]]
}

@test "vendor attributes: a change re-renders and restarts RADIUS only; tacquito.yaml is byte-identical" {
    radius_up
    local tq
    tq=$(sha256sum < "$TACCTL_CONFIG")
    tacctl scope vendor-attrs lab enable cisco,wti
    assert_success
    stub_called '^systemctl restart freeradius.service$'
    ! stub_called '^systemctl restart tacquito'
    [[ "$(sha256sum < "$TACCTL_CONFIG")" == "$tq" ]]
    grep -A7 '^	client lab.1 {' "$RCONF" | grep -q 'tacctl_send_cisco = "yes"'
    : > "$CALLS_LOG"
    tacctl scope devices prod set 10.9.9.9 juniper
    assert_success
    stub_called '^systemctl restart freeradius.service$'
    ! stub_called '^systemctl restart tacquito'
    [[ "$(sha256sum < "$TACCTL_CONFIG")" == "$tq" ]]
    grep -q '^	client prod.juniper.1 {' "$RCONF"
    tacctl status
    assert_output --partial "Vendor attributes:    enabled for 1 of 4 scope(s), 1 tagged address(es)"
    tacctl backend status radius
    assert_output --partial "Vendor attributes:    enabled for 1 of 4 scope(s), 1 tagged address(es)"
}

@test "validate: a scope served over RADIUS that sends no vendor attribute is warned about, unless it is a Linux-host scope" {
    radius_up
    tacctl config validate
    assert_success
    assert_output --partial "Vendor attributes:    not sent to the devices of scope(s) lab, prod, prod-inner, wifi over RADIUS"
    tacctl scope vendor-attrs lab enable cisco
    tacctl scope devices prod set 10.9.9.9 juniper
    # wifi: the scope of two enrolled hosts, and one /32 of theirs.
    tacctl scope prefixes wifi add 10.30.0.5/32
    tacctl scope prefixes wifi remove 10.20.0.0/16
    printf 'h1|root@10.30.0.5||wifi|10.0.0.42||radius\nh2|root@h2||wifi|10.0.0.42||radius\n' > "${TACCTL_STATE_DIR}/linux-hosts"
    tacctl config validate
    assert_success
    assert_output --partial "not sent to the devices of scope(s) prod-inner over RADIUS"
    # A host scope with a wider prefix is not told apart: warned about.
    tacctl scope prefixes wifi add 10.31.0.0/24
    tacctl config validate
    assert_output --partial "scope(s) prod-inner, wifi over RADIUS"
}

@test "uninstall: the unit is stopped and handed back, tacctl's files and logs are removed, the package stays" {
    radius_up
    plant_logs
    echo "kept" > "${TACCTL_RADIUS_DIR}/radiusd.conf"
    echo "kept" > "${TACCTL_RADIUS_LOG}/radius.log"
    tc backends_select_present
    radius_uninstall stop
    assert_success
    stub_called '^systemctl stop freeradius.service$'
    [[ ! -e "${SD}/active.freeradius" && ! -e "${SD}/enabled.freeradius" ]]
    [[ ! -e "${TACCTL_SYSTEMD_DIR}/freeradius.service.d" ]]
    radius_uninstall program
    radius_uninstall data
    assert_success
    assert_output --partial "is left installed"
    [[ ! -e "$RCONF" && ! -e "$RUSERS" && ! -e "${RDICT%/*}" ]]
    [[ ! -e "${TACCTL_LOGROTATE_DIR}/tacctl-radius" ]]
    [[ -z "$(find "$TACCTL_RADIUS_LOG" -name 'tacctl-*')" ]]
    [[ -x "$TACCTL_RADIUS_BIN" ]]
    [[ "$(cat "${TACCTL_RADIUS_DIR}/radiusd.conf")" == "kept" && "$(cat "${TACCTL_RADIUS_LOG}/radius.log")" == "kept" ]]
    radius_uninstall account
    assert_success
}

@test "uninstall: a disabled RADIUS backend is still found (its rendered files hold secrets) and somebody else's running unit is not stopped" {
    radius_up
    tacctl backend disable radius -y
    run bash -c 'set -euo pipefail; source "$1"; backends_select_present; echo "${BACKENDS_ENABLED[*]}"' _ "$TACCTL_LIB"
    assert_output "tacacs radius"
    : > "${SD}/active.freeradius"
    : > "$CALLS_LOG"
    radius_uninstall stop
    assert_success
    [[ -e "${SD}/active.freeradius" ]]
    ! stub_called '^systemctl (stop|disable)'
    radius_uninstall data
    [[ ! -e "$RCONF" && ! -e "$RUSERS" ]]
}

# bats test_tags=bash-only
@test "uninstall: a machine that merely has the FreeRADIUS package is not touched" {
    package_present
    run bash -c 'set -euo pipefail; source "$1"; backends_select_present; echo "${BACKENDS_ENABLED[*]}"' _ "$TACCTL_LIB"
    assert_output "tacacs"
}
