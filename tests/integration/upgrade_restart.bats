#!/usr/bin/env bats
# Which services 'tacctl upgrade' restarts. A restart drops every session of
# that daemon, so it follows only what the daemon reads: for tacquito a new
# binary, a changed unit or drop-in, the store migration or a changed
# tacquito.yaml; for FreeRADIUS a changed rendered file or unit drop-in. An
# upgrade with nothing new restarts nothing, and a change for one backend
# restarts that backend alone.
#
# cmd_upgrade runs as it is, with both backends enabled. What reaches
# outside the test's directories is stubbed or redirected: systemctl (keeps
# which units are active in $SD), git and go (the tacquito checkout is a
# directory, its upstream commit the file $SD/remote; a build writes the
# binary), ln for /usr/local/bin, and the packages, man page and
# /etc/{bash_completion.d,logrotate.d} writes. The management repo is a
# copy of this checkout without .git, so nothing is pulled. Each test starts
# after one upgrade (the first installs the units); the second is the one
# under test.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    local real_ln real_git
    real_ln=$(command -v ln)
    real_git=$(command -v git)
    tacctl_tmpenv_init
    tacctl_mocks_init
    export SD="${BATS_TEST_TMPDIR}/sd"
    export TACCTL_SYSTEMD_DIR="${BATS_TEST_TMPDIR}/systemd"
    export TACCTL_OVERRIDE_DIR="${TACCTL_SYSTEMD_DIR}/tacquito.service.d"
    export TACCTL_SETTLE_SECONDS=0
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    export TACQUITO_SRC="${BATS_TEST_TMPDIR}/tacquito-src"
    export TACCTL_PATCH_DIR="${BATS_TEST_TMPDIR}/patches"
    # Where the writes to /etc land.
    export SYSROOT="${BATS_TEST_TMPDIR}/root"
    export DEPLOY="${BATS_TEST_TMPDIR}/deploy"
    mkdir -p "$SD" "$TACCTL_SYSTEMD_DIR" "$TACCTL_LOGROTATE_DIR" "$TMPDIR" "$TACCTL_PATCH_DIR" "$SYSROOT" \
             "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
    RCONF="${TACCTL_RADIUS_DIR}/tacctl-radius.conf"
    RUSERS="${TACCTL_RADIUS_DIR}/tacctl-radius.users"
    RDROPIN="${TACCTL_SYSTEMD_DIR}/freeradius.service.d/tacctl.conf"
    TDROPIN="${TACCTL_OVERRIDE_DIR}/tacctl.conf"

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
    # fail-start.<unit>: the next start does not stay up (once). As for a
    # simple service, the start itself succeeds.
    if [[ -e "$SD/fail-start.$u" ]]; then rm -f "$SD/fail-start.$u" "$SD/active.$u"; exit 0; fi
    # fail-restart.<unit> holding N: the next N starts fail, with an exit
    # status (an ExecStartPre that fails, say).
    if [[ -s "$SD/fail-restart.$u" ]] && (( $(cat "$SD/fail-restart.$u") > 0 )); then
      echo $(( $(cat "$SD/fail-restart.$u") - 1 )) > "$SD/fail-restart.$u"
      rm -f "$SD/active.$u"; exit 1
    fi
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
    stub_cmd ss 'case "$*" in
  *-u*) echo "UNCONN 0 0 0.0.0.0:1812 0.0.0.0:*"; echo "UNCONN 0 0 0.0.0.0:1813 0.0.0.0:*" ;;
  *)    echo "LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))" ;;
esac'
    # The FreeRADIUS package: the daemon (its -C accepts what was rendered).
    stub_cmd apt-get 'case " $* " in *" install "*)
mkdir -p "$(dirname "$TACCTL_RADIUS_BIN")" "$TACCTL_RADIUS_DIR" "$TACCTL_RADIUS_LOG"
printf "#!/usr/bin/env bash\nexit 0\n" > "$TACCTL_RADIUS_BIN"
chmod +x "$TACCTL_RADIUS_BIN"
: > "$SD/active.freeradius"; : > "$SD/enabled.freeradius" ;; esac'
    # The tacquito checkout: HEAD is $SD/local, upstream $SD/remote. Any
    # other repository (the management repo, when a test makes it one) is
    # real git; writes to /etc/gitconfig are dropped.
    stub_cmd git "real_git=${real_git}"'
dir="$PWD"; [[ "${1:-}" == -C ]] && dir="$2"
case "$dir/" in
  "$TACQUITO_SRC"/*)
    case "$*" in
      "rev-parse --short HEAD") cut -c1-7 "$SD/local" ;;
      "rev-parse HEAD")         cat "$SD/local" ;;
      "rev-parse @{u}")         cat "$SD/remote" ;;
      "pull --quiet")           cp "$SD/remote" "$SD/local" ;;
      "log --oneline "*)        echo "$(cut -c1-7 "$SD/remote") upstream change" ;;
    esac
    exit 0 ;;
esac
[[ "$*" == "config --system "* ]] && exit 0
exec "$real_git" "$@"'
    stub_cmd go 'if [[ "$1" == build ]]; then printf "built at %s\n" "$(cat "$SD/local")" > "$3"; chmod +x "$3"; fi'
    stub_cmd ln "case \"\${*: -1}\" in /usr/local/bin/*) exit 0 ;; esac; exec ${real_ln} \"\$@\""
    echo "1111111111111111111111111111111111111111" > "$SD/local"
    cp "$SD/local" "$SD/remote"

    export UPGRADE_DRIVER="${BATS_TEST_TMPDIR}/upgrade.sh"
    cat > "$UPGRADE_DRIVER" <<'SH'
set -euo pipefail
source "$TACCTL_BIN_SCRIPT"
DEPLOY_DIR="$DEPLOY"
GO_BIN="${STUB_BIN}/go"
ensure_dependencies() { :; }
install_man_page() { :; }
eval "_real_$(declare -f update_if_changed)"
update_if_changed() {
    local dest="$2"
    if [[ "$dest" == /etc/* ]]; then
        dest="${SYSROOT}${dest}"
        mkdir -p "${dest%/*}"
    fi
    _real_update_if_changed "$1" "$dest" "$3"
}
cmd_upgrade "$@"
SH

    # The management repo: this checkout's shipped files.
    mkdir -p "${DEPLOY}/bin" "${DEPLOY}/man"
    cp -r "${TACCTL_SRC}/config" "${DEPLOY}/"
    cp "${TACCTL_SRC}/README.md" "${DEPLOY}/"
    cp "${TACCTL_SRC}/man/tacctl.1" "${DEPLOY}/man/"
    : > "${DEPLOY}/bin/tacctl.sh"

    # tacquito is installed and running from the store; RADIUS is enabled.
    printf 'built at %s\n' "$(cat "$SD/local")" > "${TACCTL_BIN}/tacquito"
    chmod +x "${TACCTL_BIN}/tacquito"
    : > "${SD}/active.tacquito"
    load_store_fixture store.radius.yaml
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
    run "$TACCTL_BIN_SCRIPT" backend enable radius -y
    assert_success

    # The first upgrade (it installs the units); the test runs the next one.
    upgrade
    assert_success
    [[ -f "$TDROPIN" && -f "$RDROPIN" ]]
    : > "$CALLS_LOG"
}

# --- helpers ---

# cmd_upgrade, colours stripped; arguments go to it. It runs from a script
# ($UPGRADE_DRIVER) so that the management repo's bin/tacctl.sh, when a test
# makes the repo a git clone, can re-execute the same thing.
upgrade() {
    run bash "$UPGRADE_DRIVER" "$@"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

# A library function under the script's own options.
tc() {
    bash -c 'set -euo pipefail; source "$1"; shift; "$@"' _ "$TACCTL_BIN_SCRIPT" "$@"
}

# What the upgrade did to services: every systemctl call that starts,
# stops, restarts or reloads a unit, one per line.
service_calls() {
    grep -E '^systemctl (restart|start|stop|reload|try-restart|reload-or-restart|condrestart|kill)( |$)|^systemctl .*--now' \
        "$CALLS_LOG" || true
}

# A file as the release before this one rendered it: different content,
# recorded in rendered.json as what tacctl wrote (so the re-render may
# replace it without calling it drift).
older_render() {
    printf '# rendered by the release before\n' >> "$1"
    tc rendered_record "$1"
    : > "$CALLS_LOG"
}

# --- nothing new ------------------------------------------------------------

@test "nothing new: a second upgrade restarts, starts, stops and reloads no service" {
    upgrade
    assert_success
    run service_calls
    assert_output ""
    run grep -c '^systemctl daemon-reload' "$CALLS_LOG"
    assert_output "0"
    run grep -c '^go ' "$CALLS_LOG"
    assert_output "0"
}

@test "nothing new: the upgrade says so (no restart line, no file updated, no RADIUS summary)" {
    upgrade
    assert_success
    refute_output --partial "Restarting"
    refute_output --partial "RADIUS: "
    assert_output --partial "0 file(s) updated."
    assert_output --partial "Scripts Updated (source unchanged at 1111111)"
}

# --- each trigger restarts its own service, once -----------------------------

@test "a new tacquito binary restarts tacquito only" {
    echo "2222222222222222222222222222222222222222" > "$SD/remote"
    upgrade
    assert_success
    assert_output --partial "Updated: 1111111 -> 2222222"
    grep -qx "built at 2222222222222222222222222222222222222222" "${TACCTL_BIN}/tacquito"
    run service_calls
    assert_output "systemctl restart tacquito.service"
}

# The build runs before tacctl pulls itself; a tacctl that changed
# re-executes the upgrade, whose own build finds the source current. The
# binary the first run built (it left the previous one as .bak) is not
# running yet: this run restarts on it.
@test "a binary built by the run before a self-update's re-exec restarts tacquito, and is then the one kept" {
    cp "${TACCTL_BIN}/tacquito" "${TACCTL_BIN}/tacquito.bak"
    printf 'built at 1111111111111111111111111111111111111111 by the run before\n' > "${TACCTL_BIN}/tacquito"
    upgrade
    assert_success
    assert_output --partial "The binary built from it is not running yet."
    assert_output --partial "Upgrade Complete: now running the tacquito binary built at 1111111"
    run grep -c '^go ' "$CALLS_LOG"
    assert_output "0"
    run service_calls
    assert_output "systemctl restart tacquito.service"
    [[ ! -e "${TACCTL_BIN}/tacquito.bak" ]]
    grep -q 'by the run before' "${TACCTL_BIN}/tacquito"
    # Once restarted, the next upgrade has nothing to do.
    : > "$CALLS_LOG"
    upgrade
    run service_calls
    assert_output ""
}

@test "the run before the re-exec hands over the commit it started from, for the summary" {
    cp "${TACCTL_BIN}/tacquito" "${TACCTL_BIN}/tacquito.bak"
    TACCTL_UPGRADE_TACQUITO_FROM=0abcdef upgrade
    assert_success
    assert_output --partial "Upgrade Complete: 0abcdef -> 1111111"
    run service_calls
    assert_output "systemctl restart tacquito.service"
}

@test "a rebuild after the re-exec (a new patch) keeps the .bak of the binary the daemon still runs, to go back to" {
    printf 'running\n' > "${TACCTL_BIN}/tacquito.bak"
    echo "2222222222222222222222222222222222222222" > "$SD/remote"
    : > "$SD/fail-start.tacquito"
    upgrade
    assert_failure
    refute_output --partial "Backed up current binary"
    assert_output --partial "Rolled back to the previous binary. Service is running."
    [[ "$(cat "${TACCTL_BIN}/tacquito")" == "running" ]]
    run service_calls
    assert_line --index 0 "systemctl restart tacquito.service"
    assert_line --index 1 "systemctl restart tacquito.service"
    [[ "${#lines[@]}" == 2 ]]
}

@test "a restart that fails with an exit status still gets the rollback, and the upgrade says so" {
    echo "2222222222222222222222222222222222222222" > "$SD/remote"
    echo 1 > "$SD/fail-restart.tacquito"
    upgrade
    assert_failure
    assert_output --partial "Tacquito failed to start after upgrade. Rolling back binary..."
    assert_output --partial "Rolled back to the previous binary. Service is running."
    grep -qx "built at 1111111111111111111111111111111111111111" "${TACCTL_BIN}/tacquito"
    run service_calls
    assert_line --index 0 "systemctl restart tacquito.service"
    assert_line --index 1 "systemctl restart tacquito.service"
    [[ "${#lines[@]}" == 2 ]]
}

# tacctl runs with umask 077: the backup of the binary must keep its mode,
# or the binary moved back after a failed restart cannot be executed by the
# tacquito user (User=tacquito).
@test "a binary rolled back after a failed restart keeps its mode" {
    chmod 0755 "${TACCTL_BIN}/tacquito"
    echo "2222222222222222222222222222222222222222" > "$SD/remote"
    echo 1 > "$SD/fail-restart.tacquito"
    upgrade
    assert_failure
    assert_output --partial "Rolled back to the previous binary. Service is running."
    run stat -c %a "${TACCTL_BIN}/tacquito"
    assert_output "755"
}

@test "a rollback restart that fails with an exit status ends in its error message" {
    echo "2222222222222222222222222222222222222222" > "$SD/remote"
    echo 2 > "$SD/fail-restart.tacquito"
    upgrade
    assert_failure
    assert_output --partial "Rolling back binary..."
    assert_output --partial "Rollback failed. Check: journalctl -u tacquito"
    grep -qx "built at 1111111111111111111111111111111111111111" "${TACCTL_BIN}/tacquito"
}

@test "a changed unit file restarts tacquito only" {
    printf '# changed in this release\n' >> "${DEPLOY}/config/backends/tacacs/tacquito.service"
    upgrade
    assert_success
    assert_output --partial "Updated: tacquito.service"
    run service_calls
    assert_output "systemctl restart tacquito.service"
}

@test "a changed tacquito drop-in restarts tacquito only" {
    older_render "$TDROPIN"
    upgrade
    assert_success
    assert_output --partial "Rendered: the listener drop-in of tacquito.service"
    run service_calls
    assert_output "systemctl restart tacquito.service"
}

@test "a changed tacquito.yaml render restarts tacquito only" {
    older_render "$TACCTL_CONFIG"
    upgrade
    assert_success
    ! grep -q 'rendered by the release before' "$TACCTL_CONFIG"
    run service_calls
    assert_output "systemctl restart tacquito.service"
}

@test "a changed RADIUS render restarts FreeRADIUS only" {
    older_render "$RUSERS"
    upgrade
    assert_success
    assert_output --partial "RADIUS: re-rendered"
    ! grep -q 'rendered by the release before' "$RUSERS"
    run service_calls
    assert_output "systemctl restart freeradius.service"
}

@test "a changed RADIUS drop-in restarts FreeRADIUS only" {
    printf '# the drop-in of the release before\n' >> "$RDROPIN"
    upgrade
    assert_success
    assert_output --partial "RADIUS: updated ${RDROPIN}."
    run service_calls
    assert_output "systemctl restart freeradius.service"
}

@test "changes for both backends restart each once" {
    older_render "$TACCTL_CONFIG"
    older_render "$RCONF"
    upgrade
    assert_success
    run service_calls
    assert_line --index 0 "systemctl restart freeradius.service"
    assert_line --index 1 "systemctl restart tacquito.service"
    [[ "${#lines[@]}" == 2 ]]
}

# --- what no daemon reads --------------------------------------------------------

@test "a new README, logrotate file, completion or template restarts nothing; a customised template is named in the summary" {
    printf '\nnew line\n' >> "${DEPLOY}/README.md"
    printf '# new\n' >> "${DEPLOY}/config/backends/tacacs/tacquito.logrotate"
    printf '# new\n' >> "${DEPLOY}/config/tacctl.bash-completion"
    printf '! new\n' >> "${DEPLOY}/config/templates/cisco.template"
    printf '# new\n' >> "${DEPLOY}/config/templates/juniper.template"
    printf '# mine\n' >> "${TACCTL_STATE_DIR}/templates/juniper.template"
    upgrade
    assert_success
    assert_output --partial "Updated: README.md"
    assert_output --partial "Updated: logrotate config"
    assert_output --partial "Updated: bash completion"
    assert_output --partial "Updated: template: cisco.template"
    assert_output --partial "Customised template kept: ${TACCTL_STATE_DIR}/templates/juniper.template"
    assert_output --partial "4 file(s) updated."
    assert_output --partial "Templates: kept 1 customised (juniper.template); this release's version of each is beside it as <name>.template.new"
    refute_output --partial "Restarting"
    run service_calls
    assert_output ""
}

# --- the management repo: a pull or a branch switch that changes tacctl -------

# Make the management repo a git clone of a scratch origin holding this
# checkout's shipped files. Branch 'other-lib' changes lib/, 'other-doc'
# only README.md. Its bin/tacctl.sh records that it was run and runs the
# upgrade again, as the new tacctl would. $WORK is a clone to push from.
deploy_git() {
    local origin="${BATS_TEST_TMPDIR}/origin.git"
    WORK="${BATS_TEST_TMPDIR}/work"
    git init -q --bare -b main "$origin"
    git init -q -b main "$WORK"
    cp -r "${DEPLOY}/." "$WORK/"
    mkdir -p "${WORK}/lib"
    echo "# release 1" > "${WORK}/lib/marker.sh"
    cat > "${WORK}/bin/tacctl.sh" <<'SH'
#!/usr/bin/env bash
echo "tacctl.sh $*" >> "$CALLS_LOG"
exec bash "$UPGRADE_DRIVER"
SH
    chmod 755 "${WORK}/bin/tacctl.sh"
    commit_push main "release 1"
    git -C "$WORK" checkout -q -b other-lib
    echo "# other-lib" >> "${WORK}/lib/marker.sh"
    commit_push other-lib "lib change"
    git -C "$WORK" checkout -q -b other-doc main
    printf '\nother-doc\n' >> "${WORK}/README.md"
    commit_push other-doc "doc change"
    git -C "$WORK" checkout -q main
    rm -rf "$DEPLOY"
    git clone -q -b main "$origin" "$DEPLOY"
    : > "$CALLS_LOG"
}

# commit_push <branch> <message>: commit everything in $WORK and push it.
commit_push() {
    git -C "$WORK" add -A
    git -C "$WORK" -c user.name=t -c user.email=t@example.com commit -q -m "$2"
    git -C "$WORK" push -q "${BATS_TEST_TMPDIR}/origin.git" "$1"
}

reexecs() { grep -c '^tacctl.sh upgrade$' "$CALLS_LOG" || true; }

@test "upgrade --branch to a branch whose lib/ differs re-executes the new tacctl once; that run has nothing more to pull" {
    deploy_git
    upgrade --branch other-lib
    assert_success
    assert_output --partial "Switched to branch 'other-lib'."
    assert_output --partial "Management scripts updated: $(git -C "$DEPLOY" rev-parse --short other-lib)"
    [[ "$(grep -c 'restarting upgrade with new version' <<< "$output")" == 1 ]]
    [[ "$(reexecs)" == 1 ]]
    # The re-executed run: on the branch, current, and it finishes.
    assert_output --partial "Management scripts already up to date."
    assert_output --partial "Scripts Updated (source unchanged at 1111111)"
    [[ "$(git -C "$DEPLOY" branch --show-current)" == "other-lib" ]]
    run service_calls
    assert_output ""
}

@test "upgrade --branch to a branch with the same bin/ and lib/ does not re-execute" {
    deploy_git
    upgrade --branch other-doc
    assert_success
    assert_output --partial "Switched to branch 'other-doc'."
    assert_output --partial "Management scripts updated: $(git -C "$DEPLOY" rev-parse --short other-doc)"
    refute_output --partial "restarting upgrade"
    [[ "$(reexecs)" == 0 ]]
    assert_output --partial "Updated: README.md"
    [[ "$(git -C "$DEPLOY" branch --show-current)" == "other-doc" ]]
}

@test "a pull on the same branch that changes lib/ re-executes once; one that changes only README.md does not" {
    deploy_git
    echo "# release 2" >> "${WORK}/lib/marker.sh"
    commit_push main "release 2"
    upgrade
    assert_success
    assert_output --partial "Management scripts updated: $(git -C "$WORK" rev-parse --short HEAD)"
    [[ "$(grep -c 'restarting upgrade with new version' <<< "$output")" == 1 ]]
    [[ "$(reexecs)" == 1 ]]
    assert_output --partial "Management scripts already up to date."

    : > "$CALLS_LOG"
    printf '\nrelease 3\n' >> "${WORK}/README.md"
    commit_push main "release 3"
    upgrade
    assert_success
    assert_output --partial "Management scripts updated: $(git -C "$WORK" rev-parse --short HEAD)"
    refute_output --partial "restarting upgrade"
    [[ "$(reexecs)" == 0 ]]
}

@test "a tacquito build before a branch switch's re-exec is restarted on once, by the re-executed run" {
    deploy_git
    echo "2222222222222222222222222222222222222222" > "$SD/remote"
    upgrade --branch other-lib
    assert_success
    [[ "$(reexecs)" == 1 ]]
    # The re-executed run takes over the restart, and the summary still
    # shows where the first run started.
    assert_output --partial "The binary built from it is not running yet."
    assert_output --partial "Upgrade Complete: 1111111 -> 2222222"
    [[ "$(grep -c 'Restarting tacquito service' <<< "$output")" == 1 ]]
    # Built once (server and hash generator), by the first run.
    run grep -c '^go build' "$CALLS_LOG"
    assert_output "2"
    run service_calls
    assert_output "systemctl restart tacquito.service"
    [[ ! -e "${TACCTL_BIN}/tacquito.bak" ]]
    grep -qx "built at 2222222222222222222222222222222222222222" "${TACCTL_BIN}/tacquito"
}
