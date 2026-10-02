#!/bin/bash
# The RADIUS container check, inside a systemd container (see run.sh):
# 'tacctl backend enable radius' for real -- package install, render, the
# daemon's config check, the unit drop-in, start -- then the radclient cases,
# mutations, listeners, drift, disable, re-enable and the uninstall phases.
#
#   flow.sh <dir with store.yaml and sec.* files>
#
# The tacctl checkout is mounted read-only at /opt/tacctl. tacquito is not in
# the container: the TACACS+ backend renders its config and fails to restart,
# which is what its warnings in the output are.
set -u
DATA="${1:?usage: flow.sh <data dir>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
pass=0; fail=0
ok()  { pass=$((pass + 1)); echo "PASS  $1"; }
bad() { fail=$((fail + 1)); echo "FAIL  $1"; }
# check <description> <command...>: PASS when the command succeeds.
check() { local d="$1"; shift; if "$@" > /dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
section() { echo; echo "=== $1"; }

if [[ -d /etc/freeradius || -x /usr/bin/apt-get ]]; then
    RADDB=/etc/freeradius/3.0; UNIT=freeradius; RUSER=freerad; LOGS=/var/log/freeradius
    pkg_verify() { dpkg --verify freeradius freeradius-config 2> /dev/null | grep ' /etc/' || true; }
    pkg_version() { dpkg-query -W -f='${Package} ${Version}\n' freeradius libcrypt1; }
else
    RADDB=/etc/raddb; UNIT=radiusd; RUSER=radiusd; LOGS=/var/log/radius
    pkg_verify() { rpm -V freeradius 2> /dev/null | grep ' /etc/' || true; }
    pkg_version() { rpm -q freeradius libxcrypt; }
fi
DROPIN="/etc/systemd/system/${UNIT}.service.d/tacctl.conf"
MYIP=$(hostname -I | cut -d' ' -f1)
rq() { # <user> <password> [<source>] -> Access-Accept | Access-Reject | none
    local out
    out=$( { printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$1" "$2"; [[ -n "${3:-}" ]] && printf 'Packet-Src-IP-Address = %s\n' "$3"; } \
        | radclient -r 1 -t 3 -S "${DATA}/sec.lab" 127.0.0.1 auth 2>&1 | grep -o 'Received Access-[A-Za-z]*' | head -1)
    echo "${out#Received }"
}
is() { [[ "$1" == "$2" ]]; }

section "setup: a store, the TACACS+ side rendered (no tacquito in the container)"
git config --global --add safe.directory /opt/tacctl 2> /dev/null
mkdir -p /etc/tacctl /etc/tacquito /var/log/tacquito
chmod 700 /etc/tacctl
sed "s#10.0.2.0/24#${MYIP%.*}.0/24#" "${DATA}/store.yaml" > /etc/tacctl/store.yaml
chmod 600 /etc/tacctl/store.yaml
ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl
tacctl config render 2>&1 | tail -2

section "backend enable radius"
tacctl backend enable radius -y; rc=$?
check "enable exits 0" is "$rc" 0
pkg_version
"$(command -v freeradius || command -v radiusd)" -v | head -1
check "unit is active" systemctl is-active --quiet "$UNIT"
check "unit is enabled" systemctl is-enabled --quiet "$UNIT"
check "the daemon runs as ${RUSER} with -n tacctl-radius" bash -c "ps -o user=,args= -C freeradius -C radiusd | grep -q '^${RUSER} .* -n tacctl-radius'"
check "artifacts are 0640 root:${RUSER}" bash -c "[[ \$(stat -c '%a %U:%G' ${RADDB}/tacctl-radius.conf) == '640 root:${RUSER}' && \$(stat -c '%a %U:%G' ${RADDB}/tacctl-radius.users) == '640 root:${RUSER}' ]]"
check "the service account can read them, nobody else" bash -c "runuser -u ${RUSER} -- cat ${RADDB}/tacctl-radius.users > /dev/null && ! runuser -u nobody -- cat ${RADDB}/tacctl-radius.users"
check "drop-in installed" test -f "$DROPIN"
check "no scratch directory left in ${RADDB}" bash -c "[[ -z \$(find ${RADDB} -maxdepth 1 -name '.tacctl-check.*') ]]"
check "the package's own configuration is unmodified" bash -c "[[ -z \"\$($(declare -f pkg_verify); pkg_verify)\" ]]"
ls -la "${RADDB}"/tacctl-radius.* "$DROPIN"

section "radclient cases"
"${HERE}/cases.sh" "$DATA"; check "all cases pass" is "$?" 0
check "the accounting record is in the detail file" grep -q 'Acct-Session-Id = "sess-0001"' "${LOGS}/tacctl-accounting.log"
check "accounting from the denied address was not recorded" bash -c "! grep -q sess-0002 ${LOGS}/tacctl-accounting.log"
check "the auth log has accepts and rejects, and no line for filtered packets" bash -c "grep -q ' Access-Accept .* user=alice\$' ${LOGS}/tacctl-auth.log && grep -q ' Access-Reject ' ${LOGS}/tacctl-auth.log && ! grep -q 'client=127.0.0.66' ${LOGS}/tacctl-auth.log"
check "logs are 0640 and owned by ${RUSER}" bash -c "[[ \$(stat -c '%a %U' ${LOGS}/tacctl-auth.log) == '640 ${RUSER}' ]]"

section "status and logs"
tacctl status 2>&1 | sed -n '/Backend: radius/,/Security Posture/p'
check "status has the RADIUS section, active and listening" bash -c "tacctl status 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -A6 'Backend: radius' | grep -q 'Listening (auth):     0.0.0.0:1812/udp'"
check "log failures --backend radius lists rejects" bash -c "tacctl log failures --backend radius | grep -q 'Access-Reject'"
check "log accounting --backend radius shows the record" bash -c "tacctl log accounting 5 --backend radius | grep -q sess-0001"
check "user show: last login from the RADIUS auth log" bash -c "tacctl user show alice | grep 'Last login' | grep -q '20[0-9][0-9]-'"
check "logrotate accepts its file" bash -c "logrotate -d /etc/logrotate.d/tacctl-radius 2>&1 | grep -q 'considering log ${LOGS}/tacctl-auth.log' && ! logrotate -d /etc/logrotate.d/tacctl-radius 2>&1 | grep -i '^error' | grep -qv 'state file'"

section "mutations reach the daemon"
BOB_PW='pass word %{x} \"q\"'
check "bob is accepted" is "$(rq bob "$BOB_PW")" Access-Accept
tacctl user disable bob > /dev/null 2>&1
check "user disable bob: rejected" is "$(rq bob "$BOB_PW")" Access-Reject
tacctl user enable bob > /dev/null 2>&1
check "user enable bob: accepted again" is "$(rq bob "$BOB_PW")" Access-Accept
tacctl scope protocols lab set tacacs > /dev/null 2>&1
check "scope protocols lab set tacacs: lab clients get no answer" is "$(rq alice Correct-Horse-1)" ""
tacctl scope protocols lab clear > /dev/null 2>&1
check "scope protocols lab clear: served again" is "$(rq alice Correct-Horse-1)" Access-Accept
# shellcheck disable=SC2016  # the dollar sign is the point
tacctl scope secret inner set 'back\slash-and-$dollar-secret' > /tmp/out 2>&1; rc=$?
check "a secret with a backslash and a dollar sign is refused (exit 1), the store keeps the old one" bash -c "[[ $rc == 1 ]] && grep -q 'backslash and a dollar' /tmp/out && tacctl scope secret inner show | grep -q inner-secret-0123456789abcdef"
check "still serving after the refused change" is "$(rq alice Correct-Horse-1)" Access-Accept

section "listeners"
tacctl config listen --backend radius --listener auth6 udp6 '[::]:1812' 2>&1 | tail -2
check "udp6 listener bound next to the udp one" bash -c "ss -uln | grep -q '\[::\]:1812' && ss -uln | grep -q '0.0.0.0:1812'"
"${HERE}/cases.sh" "$DATA" | grep -E 'IPv6|^cases'
check "IPv6 client case passes" bash -c "'${HERE}/cases.sh' '$DATA' | grep -q '^PASS  IPv6'"
tacctl config listen --backend radius --listener auth udp 192.0.2.99:1812 > /tmp/out 2>&1; rc=$?
check "an address the daemon cannot bind is rolled back (exit 1), unit active on the old listener" bash -c "[[ $rc == 1 ]] && systemctl is-active --quiet $UNIT && ss -uln | grep -q '0.0.0.0:1812' && ! grep -q 192.0.2.99 ${RADDB}/tacctl-radius.conf"
tacctl config listen --backend radius --listener auth6 reset > /dev/null 2>&1
check "listener reset removes the udp6 listener" bash -c "! ss -uln | grep -q '\[::\]:1812'"

section "drift"
echo "# hand edit" >> "${RADDB}/tacctl-radius.users"
tacctl user disable bob > /tmp/out 2>&1; rc=$?
check "a hand-edited users file refuses a mutation (exit 3)" is "$rc" 3
tacctl config render --force > /dev/null 2>&1
check "config render --force replaces it and keeps a copy" bash -c "! grep -q 'hand edit' ${RADDB}/tacctl-radius.users && ls /etc/tacctl/backups/legacy/tacctl-radius.users.drift.* > /dev/null"
check "config validate is clean for radius" bash -c "tacctl config validate 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -A1 'Backend radius' | grep -q 'up to date'"

section "systemctl reload (config check, then HUP)"
systemctl reload "$UNIT"; check "reload succeeds" is "$?" 0
check "still serving after reload" is "$(rq alice Correct-Horse-1)" Access-Accept

section "backend disable radius"
tacctl backend disable radius -y 2>&1 | tail -3
check "unit inactive" bash -c "! systemctl is-active --quiet $UNIT"
check "unit not enabled" bash -c "! systemctl is-enabled --quiet $UNIT"
check "drop-in removed, unit is the package's again" bash -c "[[ ! -e $DROPIN ]] && ! systemctl cat $UNIT | grep -q tacctl"
check "rendered files stay" test -f "${RADDB}/tacctl-radius.conf"
check "nothing listens on 1812" bash -c "! ss -uln | grep -q ':1812 '"
# The package's own configuration under the package's unit: "somebody's RADIUS
# server". On EL9 the pristine package does not start (its EAP module wants
# certificates nobody generated), tacctl or no tacctl; the takeover check is
# skipped there.
if systemctl start "$UNIT" 2> /dev/null && sleep 2 && systemctl is-active --quiet "$UNIT"; then
    ok "the package's own configuration still starts under the unit (untouched)"
    tacctl backend enable radius -y > /tmp/out 2>&1; rc=$?
    check "enable is refused while somebody runs the unit, and the unit is left running" bash -c "[[ $rc == 1 ]] && grep -q \"somebody's RADIUS server\" /tmp/out && systemctl is-active --quiet $UNIT && [[ ! -e $DROPIN ]]"
    systemctl stop "$UNIT"
else
    echo "SKIP  the package's own configuration does not start on this distro as shipped; takeover refusal not exercised"
    systemctl reset-failed "$UNIT" 2> /dev/null || true
fi

section "enable again (installed: no package install)"
tacctl backend enable radius -y 2>&1 | tail -2
check "active and enabled" bash -c "systemctl is-active --quiet $UNIT && systemctl is-enabled --quiet $UNIT"
check "cases pass again" "${HERE}/cases.sh" "$DATA"

section "uninstall phases (stop, program, data, account)"
bash -c 'set -euo pipefail; source /opt/tacctl/bin/tacctl.sh; backends_select_present; echo "selected: ${BACKENDS_ENABLED[*]}"; for p in stop program data account; do backend_radius_uninstall "$p"; done'
check "unit stopped and not enabled" bash -c "! systemctl is-active --quiet $UNIT && ! systemctl is-enabled --quiet $UNIT"
check "tacctl's files are gone from ${RADDB}, the systemd directory, logrotate.d and ${LOGS}" bash -c "[[ -z \$(ls ${RADDB} | grep tacctl) && ! -e $DROPIN && ! -e /etc/logrotate.d/tacctl-radius && -z \$(ls ${LOGS} | grep tacctl) ]]"
check "the package and its configuration are still there, unmodified" bash -c "[[ -f ${RADDB}/radiusd.conf && -z \"\$($(declare -f pkg_verify); pkg_verify)\" ]]"

echo
echo "flow: ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
