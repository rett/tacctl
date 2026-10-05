#!/bin/bash
# The Linux-host check: 'tacctl host enroll|sync|unenroll' for real, over
# SSH, from a server container that runs tacctl with real FreeRADIUS (and
# real tacquito) to a client container of the distribution under test, then
# SSH password logins and sudo on the client. Rootless podman; nothing on
# this machine is touched outside podman and a temp directory.
#
#   tests/containers/hosts/run.sh <client> <cycle> [--server <distro>] [--keep]
#
#   <client>   ubuntu-noble debian-trixie debian-bookworm
#              almalinux-8 almalinux-9 almalinux-10 rocky-8 rocky-9 rocky-10
#   <cycle>    radius   enroll with --method radius, the login cases, unenroll
#              tacplus  the same with --method tacplus
#              switch   enroll tacplus, switch to radius, switch back, unenroll
#              probe    no enroll: what pam_radius_auth returns per case
#   --server   ubuntu-noble (default; FreeRADIUS 3.2.x and tacquito) or
#              almalinux-9 (FreeRADIUS 3.0.27; radius and probe only)
#   --keep     leave both containers (thc-server, thc-client-<client>)
#
# Prints PASS / FAIL / NOTE lines; exit 0 when nothing failed. Images are
# built once and kept (localhost/tacctl-host-check:{server,client}-<distro>).
# tacquito is not built here: the server image takes /usr/local/bin/tacquito
# from this machine, and without it only radius and probe can run. Needs
# python3-bcrypt in the server image (installed there), nothing else here. The
# server image builds tacctl from this checkout with its bootstrap
# (bin/tacctl.sh installs Go, verified, and builds /usr/local/bin/tacctl).
# shellcheck disable=SC2016  # the single-quoted scripts run inside the containers
set -uo pipefail
CLIENT="${1:?usage: run.sh <client> <radius|tacplus|switch|probe> [--server <distro>] [--keep]}"
CYCLE="${2:?usage: run.sh <client> <radius|tacplus|switch|probe> [--server <distro>] [--keep]}"
shift 2
SERVER="ubuntu-noble"; KEEP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --server) SERVER="${2:?--server needs a distro}"; shift 2 ;;
        --keep) KEEP="yes"; shift ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../../.." && pwd)"
NET="tacctl-host-check"
S="thc-server"
C="thc-client-${CLIENT}"

case "$CLIENT" in
    ubuntu-noble)    BASE=docker.io/library/ubuntu:noble ;;
    debian-trixie)   BASE=docker.io/library/debian:trixie ;;
    debian-bookworm) BASE=docker.io/library/debian:bookworm ;;
    almalinux-8|almalinux-9|almalinux-10) BASE="docker.io/library/almalinux:${CLIENT#almalinux-}" ;;
    rocky-8|rocky-9) BASE="docker.io/library/rockylinux:${CLIENT#rocky-}" ;;
    rocky-10)        BASE=docker.io/rockylinux/rockylinux:10 ;;
    *) echo "unknown client: ${CLIENT}" >&2; exit 2 ;;
esac
case "$CYCLE" in
    radius|probe) WANT=radius ;;
    tacplus) WANT=tacplus ;;
    switch) WANT=both ;;
    *) echo "unknown cycle: ${CYCLE}" >&2; exit 2 ;;
esac
case "$SERVER" in
    ubuntu-noble) SBASE=docker.io/library/ubuntu:noble
        SSETUP='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus python3 python3-yaml python3-bcrypt iproute2 procps logrotate git diffutils openssh-client nftables autoconf automake libtool gnulib libpam0g-dev build-essential wget ca-certificates > /dev/null' ;;
    almalinux-9) SBASE=docker.io/library/almalinux:9
        [[ "$WANT" == "radius" ]] || { echo "--server almalinux-9 runs the radius and probe cycles only" >&2; exit 2; }
        SSETUP='dnf install -y -q systemd python3 python3-pyyaml python3-pip iproute procps-ng logrotate git findutils diffutils openssh-clients nftables wget > /dev/null && pip3 install -q bcrypt' ;;
    *) echo "unknown server: ${SERVER}" >&2; exit 2 ;;
esac
SIMAGE="localhost/tacctl-host-check:server-${SERVER}"
CIMAGE="localhost/tacctl-host-check:client-${CLIENT}"

WORK=$(mktemp -d)
cleanup() {
    if [[ -z "$KEEP" ]]; then podman rm -f -t 0 "$S" "$C" > /dev/null 2>&1 || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

pass=0; fail=0
ok()   { pass=$((pass + 1)); echo "PASS  $1"; }
bad()  { fail=$((fail + 1)); echo "FAIL  $1"; }
note() { echo "NOTE  $1"; }
section() { echo; echo "=== $1"; }
s() { podman exec "$S" "$@"; }
c() { podman exec "$C" "$@"; }
tacctl() { podman exec "$S" tacctl "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; return "${PIPESTATUS[0]}"; }
# check <description> <command...>: PASS when the command succeeds.
check() { local d="$1"; shift; if "$@" > /dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }
# login <user> <password> <command...> -> the command's output and 'rc=N t=S'
login() { podman exec "$C" /check/sshtry.sh "$@"; }
# expect <description> <regex> <text>: PASS when the text matches.
expect() {
    if grep -qE -- "$2" <<< "$3"; then ok "$1"; else bad "$1   (wanted /$2/, got: $(tr '\n' ' ' <<< "$3"))"; fi
}
secs() { sed -n 's/.*rc=[0-9]* t=\([0-9]*\).*/\1/p' <<< "$1" | tail -1; }

# --- images -------------------------------------------------------------------
podman network exists "$NET" || podman network create "$NET" > /dev/null
if ! podman image exists "$SIMAGE"; then
    echo "--- building ${SIMAGE} from ${SBASE}"
    podman rm -f -t 0 "${S}-build" > /dev/null 2>&1 || true
    podman run -d --name "${S}-build" -v "${REPO}:/opt/tacctl:ro" "$SBASE" sleep infinity > /dev/null
    podman exec "${S}-build" bash -c "$SSETUP" || exit 1
    # tacctl itself, built from this checkout by its bootstrap.
    podman exec "${S}-build" bash -c 'git config --global --add safe.directory /opt/tacctl
        /opt/tacctl/bin/tacctl.sh version' | tail -1 || exit 1
    if [[ "$SERVER" == "ubuntu-noble" ]]; then
        # The pinned pam_tacplus source, prepared as 'tacctl install' would.
        # Every command but 'version' wants a store (it says "Is tacctl
        # installed?" otherwise): an empty one is enough here, and goes again
        # (server-setup.sh writes the real one).
        podman exec "${S}-build" bash -c 'set -euo pipefail
            mkdir -p /etc/tacctl && printf "version: 1\n" > /etc/tacctl/store.yaml
            tacctl config linux build; rm -rf /etc/tacctl' | tail -1 || exit 1
        if [[ -x /usr/local/bin/tacquito ]]; then
            podman cp /usr/local/bin/tacquito "${S}-build:/usr/local/bin/tacquito"
        else
            echo "NOTE  no /usr/local/bin/tacquito on this machine: the server image cannot run the tacplus and switch cycles"
        fi
    fi
    podman commit -q "${S}-build" "$SIMAGE" > /dev/null
    podman rm -f -t 0 "${S}-build" > /dev/null
fi
if ! podman image exists "$CIMAGE"; then
    echo "--- building ${CIMAGE} from ${BASE}"
    podman rm -f -t 0 "${C}-build" > /dev/null 2>&1 || true
    podman run -d --name "${C}-build" -v "${HERE}:/check:ro" "$BASE" sleep infinity > /dev/null
    podman exec "${C}-build" /check/client-prep.sh || exit 1
    podman commit -q "${C}-build" "$CIMAGE" > /dev/null
    podman rm -f -t 0 "${C}-build" > /dev/null
fi

# --- containers ---------------------------------------------------------------
podman rm -f -t 0 "$S" "$C" > /dev/null 2>&1 || true
# SYS_ADMIN: the Debian FreeRADIUS unit's sandboxing needs it in a rootless
# container. NET_ADMIN: the check makes the server unreachable with nft.
podman run -d --name "$S" --network "$NET" --systemd=always --cap-add SYS_ADMIN --cap-add NET_ADMIN \
    -v "${REPO}:/opt/tacctl:ro" "$SIMAGE" /sbin/init > /dev/null || exit 1
podman run -d --name "$C" --network "$NET" --cap-add AUDIT_WRITE -v "${HERE}:/check:ro" \
    "$CIMAGE" /usr/sbin/sshd -D -e > /dev/null || exit 1
sleep 4
PY=$(c bash -c 'command -v python3 || echo /usr/libexec/platform-python')
SIP=$(s hostname -I | cut -d' ' -f1)
CIP=$(c hostname -I | cut -d' ' -f1)
# tacctl runs as root in the server container and logs in to the client as root.
ssh-keygen -q -t ed25519 -N '' -f "${WORK}/key"
podman cp "${WORK}/key" "${S}:/root/.ssh-key" 
s bash -c 'mkdir -p /root/.ssh && chmod 700 /root/.ssh && mv /root/.ssh-key /root/.ssh/id_ed25519 && chown root:root /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519 && printf "Host *\n  StrictHostKeyChecking accept-new\n" > /root/.ssh/config'
podman cp "${WORK}/key.pub" "${C}:/root/.ssh/authorized_keys"
c bash -c 'chown root:root /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys'

section "server (${SERVER}, ${SIP}) and client (${CLIENT}, ${CIP})"
s /opt/tacctl/tests/containers/hosts/server-setup.sh "$WANT" || { bad "server setup"; exit 1; }
c bash -c '. /etc/os-release; echo "client: ${PRETTY_NAME}; $(ssh -V 2>&1); $(sudo -V | head -1); $( (rpm -q pam 2>/dev/null || dpkg-query -W -f "libpam-modules \${Version}" libpam-modules) | head -1)"'

# The block: everything from the client is dropped at the server, so a
# request gets no answer and no ICMP error, as behind a firewall.
block()   { s nft add table inet thc && s nft add chain inet thc in '{ type filter hook input priority 0 ; }' && s nft add rule inet thc in ip saddr "$CIP" drop; }
unblock() { s nft delete table inet thc; }

# What a host must get back at unenroll: every PAM file, sudoers, tacctl's
# own files, and no module of tacctl's in the module directory.
snapshot() {
    c bash -c 'cd / && { find etc/pam.d etc/sudoers etc/sudoers.d -type f -exec sha256sum {} + 2> /dev/null
        ls -d etc/tacctl* etc/xdg/tacctl 2> /dev/null
        find usr/lib usr/lib64 lib lib64 \( -name "pam_tacplus.so" -o -name "libtac.so*" \) 2> /dev/null; } | sort'
}
pkg_versions() {
    c bash -c 'rpm -q pam_radius epel-release 2> /dev/null | grep -v "not installed"; dpkg-query -W -f "\${Package} \${Version}\n" libpam-radius-auth 2> /dev/null; true' | paste -sd' '
}
radius_log() { s bash -c 'cat /var/log/freeradius/tacctl-auth.log /var/log/radius/tacctl-auth.log 2> /dev/null'; }
radius_acct() { s bash -c 'cat /var/log/freeradius/tacctl-accounting.log /var/log/radius/tacctl-accounting.log 2> /dev/null'; }
host_secret() { tacctl scope secret linux-c1 show | sed -n 's/^ *Value: *//p'; }

# --- probe: what pam_radius_auth returns --------------------------------------
if [[ "$CYCLE" == "probe" ]]; then
    section "pam_radius_auth return codes (${CLIENT})"
    c bash -c 'if command -v apt-get > /dev/null; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libpam-radius-auth > /dev/null 2>&1
        else dnf install -y -q epel-release > /dev/null 2>&1; dnf install -y -q pam_radius > /dev/null 2>&1; fi'
    pkg_versions
    tacctl scope add probe --prefixes "${CIP}/32" --secret probe-secret-0123456789 --protocols radius > /dev/null
    tacctl user scope alice add probe > /dev/null
    c bash -c "useradd -m alice 2> /dev/null; useradd -m bob 2> /dev/null
        py=\$(command -v python3 || echo /usr/libexec/platform-python)
        mk() { n=\$1; shift; printf '%s\n' \"\$@\" > /root/rad-\$n.conf; chmod 600 /root/rad-\$n.conf
               printf '%s\n' \"auth required pam_radius_auth.so conf=/root/rad-\$n.conf\" \"account required pam_radius_auth.so conf=/root/rad-\$n.conf\" \"session required pam_radius_auth.so conf=/root/rad-\$n.conf\" \"password required pam_radius_auth.so conf=/root/rad-\$n.conf\" > /etc/pam.d/rt-\$n; }
        mk ok '${SIP}:1812 probe-secret-0123456789 3'
        mk badsecret '${SIP}:1812 not-the-secret 3'
        mk closed '${SIP}:1899 probe-secret-0123456789 3'
        mk nodns 'no-such-host.invalid:1812 probe-secret-0123456789 3'
        mk noport '${SIP} probe-secret-0123456789 3'
        printf '%s\n' 'auth required pam_radius_auth.so conf=/root/missing.conf' > /etc/pam.d/rt-noconf
        p() { echo \"-- \$1\"; shift; \$py /check/pamprobe.py \"\$@\"; }
        p 'right password: auth, account, session' rt-ok alice Alice-Net-Pw-1 auth,acct,open,close
        p 'wrong password' rt-ok alice wrong auth
        p 'user not in the scope' rt-ok bob Bob-Net-Pw-1 auth
        p 'empty password' rt-ok alice '' auth
        p 'wrong shared secret' rt-badsecret alice Alice-Net-Pw-1 auth
        p 'port nobody listens on' rt-closed alice Alice-Net-Pw-1 auth
        p 'server name that does not resolve' rt-nodns alice Alice-Net-Pw-1 auth
        p 'server file missing' rt-noconf alice Alice-Net-Pw-1 auth
        p 'no port in the server file' rt-noport alice Alice-Net-Pw-1 auth
        p 'account and session without auth (an SSH-key login)' rt-ok alice x acct,open,close
        p 'password change' rt-ok alice Alice-Net-Pw-1 chauthtok"
    block > /dev/null
    c bash -c 'py=$(command -v python3 || echo /usr/libexec/platform-python)
        echo "-- server silent (packets dropped): auth with retry=0, =1, =2; session"
        for r in 0 1 2; do sed -i "s/conf=\/root\/rad-ok.conf.*/conf=\/root\/rad-ok.conf retry=$r/" /etc/pam.d/rt-ok; $py /check/pamprobe.py rt-ok alice Alice-Net-Pw-1 auth; done
        $py /check/pamprobe.py rt-ok alice x open,close'
    unblock > /dev/null
    echo "-- accounting records the server wrote for the session above"
    radius_acct | grep -E 'Acct-Status-Type|NAS-IP-Address' | sort | uniq -c
    exit 0
fi

# --- the login cases, for the method the host has now -------------------------
A_PW='Alice-Net-Pw-1'; B_PW='Bob-Net-Pw-1'; CN_PW='Carl-Net-Pw-1'; CL_PW='Carl-Local-Pw-1'; L_PW='Local-Admin-Pw-1'
D_PW='Dave-Net-Pw-1'

# basic_cases <method>: the short set, also run after each switch.
basic_cases() {
    local m="$1" out
    out=$(login alice "$A_PW" 'id -un; id -nG')
    expect "[$m] alice logs in over SSH with the network password" '^alice$' "$out"
    expect "[$m] alice is in tac-users and tac-superuser" 'tac-users.*tac-superuser|tac-superuser.*tac-users' "$out"
    expect "[$m] alice with a wrong password is refused" 'rc=255' "$(login alice 'not-her-password' true)"
    expect "[$m] alice: sudo with the network password gives root" '^0$' "$(login alice "$A_PW" "printf '%s\n' '$A_PW' | sudo -S -k -p '' id -u")"
    expect "[$m] ladm (local administrator, not a tacctl user) logs in with the local password" '^ladm$' "$(login ladm "$L_PW" 'id -un')"
}

full_cases() {
    local m="$1" out t secret
    basic_cases "$m"
    expect "[$m] alice: sudo with a wrong password is refused" 'rc=1' "$(login alice "$A_PW" "printf '%s\n' 'wrong' | sudo -S -k -p '' id -u")"
    expect "[$m] alice: sudo -i with the network password gives root" '^0$' "$(login alice "$A_PW" "printf '%s\n' '$A_PW' | sudo -S -k -p '' -i id -u")"
    expect "[$m] carl (a local account named like a tacctl user) logs in with his local password" '^carl$' "$(login carl "$CL_PW" 'id -un')"
    expect "[$m] carl's network password is refused: no tacctl account for him here" 'rc=255' "$(login carl "$CN_PW" true)"
    expect "[$m] dave (readonly) logs in with the network password" '^dave$' "$(login dave "$D_PW" 'id -un')"
    expect "[$m] dave (readonly) may not sudo" 'not (allowed|in the sudoers)|rc=1' "$(login dave "$D_PW" "printf '%s\n' '$D_PW' | sudo -S -k -p '' id -u")"
    expect "[$m] ladm: sudo with the local password gives root" '^0$' "$(login ladm "$L_PW" "printf '%s\n' '$L_PW' | sudo -S -k -p '' id -u")"

    # The other services, through a PAM client run as root (what login and
    # the display manager's worker are), and once as the user (what KDE's
    # lock screen is).
    out=$(c "$PY" /check/pamprobe.py login alice "$A_PW" auth,acct,open,close)
    expect "[$m] console login service: auth, account and session succeed for alice" '^auth +rc=0 .*acct +rc=0 .*open +rc=0 .*close +rc=0 ' "$(tr '\n' ' ' <<< "$out")"
    expect "[$m] console login service: a wrong password is an authentication failure" '^auth +rc=7 ' "$(c "$PY" /check/pamprobe.py login alice wrong auth)"
    expect "[$m] gdm-password (stand-in file): auth and account succeed for alice" '^auth +rc=0 .*acct +rc=0 ' "$(c "$PY" /check/pamprobe.py gdm-password alice "$A_PW" auth,acct | tr '\n' ' ')"
    expect "[$m] gdm-password: ladm with the local password" '^auth +rc=0 ' "$(c "$PY" /check/pamprobe.py gdm-password ladm "$L_PW" auth)"
    out=$(c runuser -u alice -- "$PY" /check/pamprobe.py gdm-password alice "$A_PW" auth 2>&1)
    if grep -q '^auth +rc=0 ' <<< "$out"; then
        bad "[$m] a PAM client that is not root (KDE's lock screen) authenticated alice: $out"
    else
        ok "[$m] a PAM client that is not root (KDE's lock screen) cannot authenticate alice: $(tr '\n' ' ' <<< "$out")"
    fi

    # A user the server no longer lets in from this scope, before any sync:
    # the account is still on the host.
    tacctl user scope bob remove linux-c1 > /dev/null
    expect "[$m] bob, removed from the scope on the server (no sync yet), is refused" 'rc=255' "$(login bob "$B_PW" true)"
    check "[$m] bob's account is still on the host until the sync" c id bob
    tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
    check "[$m] host sync succeeds and deletes bob's account (userdel), with his group" bash -c "[[ $rc == 0 ]] && grep -q \"Deleted account 'bob'\" '${WORK}/sync.out' && ! podman exec '$C' id bob && ! podman exec '$C' getent group bob"
    check "[$m] no terminal and no --remove-home: bob's home is kept and reported" bash -c "grep -q 'home kept: /home/bob' '${WORK}/sync.out' && podman exec '$C' test -d /home/bob"
    expect "[$m] bob is refused after the sync too" 'rc=255' "$(login bob "$B_PW" true)"

    # A disabled user: expired, kept; enabled again: back.
    tacctl user disable dave > /dev/null
    tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
    check "[$m] host sync expires disabled dave's account and keeps it" bash -c "[[ $rc == 0 ]] && grep -q \"'dave' has no\" '${WORK}/sync.out' && podman exec '$C' id dave && podman exec '$C' getent shadow dave | cut -d: -f8 | grep -qx 1 && podman exec '$C' test -d /home/dave"
    expect "[$m] disabled dave is refused" 'rc=255' "$(login dave "$D_PW" true)"
    tacctl user enable dave > /dev/null
    tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
    check "[$m] enabled again, dave's account is re-activated" bash -c "[[ $rc == 0 ]] && grep -q \"Re-activated account 'dave'\" '${WORK}/sync.out'"
    expect "[$m] dave logs in again" '^dave$' "$(login dave "$D_PW" 'id -un')"

    # A removed user with --remove-home: the home goes too.
    if c id erin > /dev/null 2>&1; then
        c bash -c 'cd /home/erin && echo note > file && ln -s /etc etc-link'
        tacctl user scope erin remove linux-c1 > /dev/null
        tacctl host sync c1 --remove-home > "${WORK}/sync.out"; rc=$?
        check "[$m] host sync --remove-home deletes erin's account and home (not what a link in it points to)" bash -c "[[ $rc == 0 ]] && grep -q 'Deleted home /home/erin.' '${WORK}/sync.out' && ! podman exec '$C' id erin && ! podman exec '$C' test -e /home/erin && podman exec '$C' test -f /etc/passwd"
        check "[$m] erin's UID stays reserved on the server" bash -c "podman exec '$S' grep -qx 'erin:20004' /etc/tacctl/linux-uids"
    fi

    # Server unreachable.
    block > /dev/null || bad "could not block the server"
    out=$(login ladm "$L_PW" 'id -un'); t=$(secs "$out")
    expect "[$m] server unreachable: ladm still logs in" '^ladm$' "$out"
    check "[$m] server unreachable: ladm is not delayed (${t}s)" test "${t:-99}" -le 2
    out=$(login ladm "$L_PW" "printf '%s\n' '$L_PW' | sudo -S -k -p '' id -u")
    expect "[$m] server unreachable: ladm can still sudo" '^0$' "$out"
    out=$(login alice "$A_PW" true); t=$(secs "$out")
    expect "[$m] server unreachable: alice (no local password) is refused" 'rc=255' "$out"
    note "[$m] server unreachable: alice's refusal took ${t}s"
    out=$(login carl "$CL_PW" 'id -un'); t=$(secs "$out")
    expect "[$m] server unreachable: carl (not in tac-users) logs in with his local password" '^carl$' "$out"
    check "[$m] server unreachable: carl is not delayed (${t}s)" test "${t:-99}" -le 2
    unblock > /dev/null || bad "could not unblock the server"
    expect "[$m] server back: alice logs in again" '^alice$' "$(login alice "$A_PW" 'id -un')"

    # A wrong shared secret on the host: tacctl users are refused, local
    # accounts outside tac-users are not affected.
    secret=$(host_secret)
    if [[ "$m" == "radius" ]]; then
        c sed -i "s|${secret}|wrong-secret-wrong-secret-wrong|" /etc/tacctl-pam_radius.conf
    else
        c sed -i "s|secret=${secret}|secret=wrong-secret-wrong-secret-wrong|" /etc/pam.d/tacctl-auth /etc/pam.d/tacctl-account /etc/pam.d/tacctl-session
    fi
    out=$(login alice "$A_PW" true); t=$(secs "$out")
    expect "[$m] wrong shared secret on the host: alice is refused" 'rc=255' "$out"
    note "[$m] wrong shared secret: alice refused after ${t}s"
    expect "[$m] wrong shared secret: carl's local account is unaffected" '^carl$' "$(login carl "$CL_PW" 'id -un')"
    expect "[$m] wrong shared secret: ladm is unaffected" '^ladm$' "$(login ladm "$L_PW" 'id -un')"
    # Re-enrolling (no --method: the host keeps the one it has) repairs it.
    tacctl host enroll "root@${CIP}" --name c1 > "${WORK}/reenroll.out"; rc=$?
    check "[$m] re-enroll without --method succeeds and keeps the method" bash -c "[[ $rc == 0 ]] && ! grep -q Switching '${WORK}/reenroll.out'"
    expect "[$m] after the re-enroll alice logs in again" '^alice$' "$(login alice "$A_PW" 'id -un')"
}

# where_secret <method>: the secret is where the method keeps it, root-only,
# and nowhere else.
where_secret() {
    local m="$1" secret
    secret=$(host_secret)
    if [[ "$m" == "radius" ]]; then
        check "[$m] the secret is in /etc/tacctl-pam_radius.conf, 0600 root:root" c bash -c "grep -q ' ${secret} ' /etc/tacctl-pam_radius.conf && [[ \$(stat -c '%a %U:%G' /etc/tacctl-pam_radius.conf) == '600 root:root' ]]"
        check "[$m] no secret and no pam_tacplus on any PAM line" c bash -c "! grep -rqF -e '${secret}' -e pam_tacplus /etc/pam.d"
        check "[$m] nothing of pam_tacplus on the host" c bash -c '[[ -z $(find /usr/lib /usr/lib64 \( -name pam_tacplus.so -o -name "libtac.so*" \) 2> /dev/null) && ! -e /var/lib/tacctl-client/module && ! -e /var/lib/tacctl-client/files ]]'
        check "[$m] the packaged pam_radius_auth.conf is not used and was not edited" c bash -c "! grep -rq 'conf=/etc/pam_radius' /etc/pam.d && grep -rq 'conf=/etc/tacctl-pam_radius.conf' /etc/pam.d/tacctl-auth && ! grep -q '${SIP}' /etc/pam_radius.conf /etc/pam_radius_auth.conf 2> /dev/null"
    else
        check "[$m] the secret is on the pam_tacplus lines, files 0600 root:root" c bash -c "grep -q 'secret=${secret} ' /etc/pam.d/tacctl-auth && [[ \$(stat -c '%a %U:%G' /etc/pam.d/tacctl-auth) == '600 root:root' ]]"
        check "[$m] no pam_radius_auth line and no RADIUS server file" c bash -c '! grep -rq pam_radius /etc/pam.d && [[ ! -e /etc/tacctl-pam_radius.conf ]]'
    fi
    check "[$m] the host records its method" c grep -qx "$m" /var/lib/tacctl-client/method
    expect "[$m] the registry and 'host list' show the method" "c1 +root@${CIP} +linux-c1 +${SIP} +${m} " "$(tacctl host list)"
    expect "[$m] the host's scope serves the method's protocol only" "protocols: $([[ $m == radius ]] && echo radius || echo tacacs)\$" "$(tacctl scope protocols linux-c1)"
}

enroll() { # <method> [extra args]
    local m="$1"; shift
    tacctl host enroll "root@${CIP}" --name c1 --method "$m" "$@" > "${WORK}/enroll.out"; rc=$?
    sed 's/^/    | /' "${WORK}/enroll.out" | grep -vE '^\s+\| *$' | grep -E 'INFO|WARN|ERROR'
    return $rc
}

FIRST="$CYCLE"; [[ "$CYCLE" == "switch" ]] && FIRST="tacplus"

section "before: snapshot, then enroll with --method ${FIRST}"
snapshot > "${WORK}/before"
check "nothing of tacctl on the host yet" c bash -c '[[ ! -e /var/lib/tacctl-client && ! -e /etc/pam.d/tacctl-auth ]]'
enroll "$FIRST"; check "host enroll --method ${FIRST} exits 0" test $? -eq 0
[[ "$FIRST" == "radius" ]] && note "installed by the enrollment: $(pkg_versions)"
check "enroll said there are no users in the scope yet" grep -q "No users are in scope 'linux-c1' yet" "${WORK}/enroll.out"

section "users: alice (superuser), bob (operator), dave and erin (readonly), carl (readonly; the host has a local carl)"
# carl as an earlier release left an adopted account: in tacctl's groups
# and listed in the 'adopted' state file.
c bash -c 'usermod -aG tac-users,tac-readonly carl && echo carl > /var/lib/tacctl-client/adopted'
carl_before=$(c getent passwd carl); carl_shadow=$(c getent shadow carl); carl_groups=$(c id -nG carl | tr ' ' '\n' | grep -v '^tac-' | sort | paste -sd' ')
for u in alice bob carl dave erin; do tacctl user scope "$u" add linux-c1 > /dev/null; done
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
check "host sync refuses carl (a local account tacctl did not create), goes on, and says so in its summary" bash -c "[[ $rc == 0 ]] && grep -q \"'carl': this host has a local account of that name that tacctl did not create\" '${WORK}/sync.out' && grep -q 'c1: synced (4 users; 1 refused: carl)' '${WORK}/sync.out'"
check "the adopted carl is reported once, taken out of tacctl's groups, and forgotten" bash -c "grep -q 'adopted are no longer tracked: carl' '${WORK}/sync.out' && grep -q \"'carl': removed from tacctl's groups (tac-users, tac-readonly); it is a plain local account again.\" '${WORK}/sync.out' && ! podman exec '$C' test -e /var/lib/tacctl-client/adopted"
check "nothing else of carl's account changed (passwd and shadow lines, other groups)" bash -c "[[ \"\$(podman exec '$C' getent passwd carl)\" == '${carl_before}' && \"\$(podman exec '$C' getent shadow carl)\" == '${carl_shadow}' && \"\$(podman exec '$C' id -nG carl | tr ' ' '\\n' | sort | paste -sd' ')\" == '${carl_groups}' ]]"
check "every account tacctl created has a UID in 20000-29999" bash -c "for u in alice bob dave erin; do id=\$(podman exec '$C' id -u \$u) && (( id >= 20000 && id <= 29999 )) || exit 1; done"
LABEL="TACACS+"; [[ "$FIRST" == "radius" ]] && LABEL="RADIUS"
check "alice's account: UID 20000, locked password, named 'alice (${LABEL})'" c bash -c "[[ \$(id -u alice) == 20000 && \$(getent passwd alice | cut -d: -f5) == 'alice (${LABEL})' ]] && getent shadow alice | cut -d: -f2 | grep -q '^!'"

section "cases (${FIRST})"
where_secret "$FIRST"
full_cases "$FIRST"
if [[ "$FIRST" == "radius" ]]; then
    expect "[radius] the server's auth log has alice's accept from this host" "Access-Accept scope=linux-c1 device=generic client=${CIP} nas=sshd .*user=alice" "$(radius_log)"
    expect "[radius] and sudo's" "Access-Accept scope=linux-c1 device=generic client=${CIP} nas=sudo.* .*user=alice" "$(radius_log)"
    expect "[radius] and bob's reject for the scope" "Access-Reject scope=linux-c1 device=generic client=${CIP} .*user=bob" "$(radius_log)"
    if c grep -q pam_radius_auth /etc/pam.d/tacctl-session; then
        expect "[radius] session accounting: Start and Stop records for alice" 'Acct-Status-Type = Start' "$(radius_acct | grep -A8 'User-Name = "alice"')"
        if radius_acct | grep -qE 'Acct-Status-Type = [0-9]'; then bad "[radius] malformed accounting records"; else ok "[radius] no malformed accounting record"; fi
    else
        note "[radius] no session accounting line on this host: $(grep -o 'No session accounting.*' "${WORK}/enroll.out" | head -1)"
        if radius_acct | grep -q User-Name; then bad "[radius] accounting records reached the server"; else ok "[radius] and no accounting record reached the server"; fi
    fi
    check "[radius] the include of the rule-less tacctl-account file is harmless (logins above passed)" c bash -c "! grep -v '^#' /etc/pam.d/tacctl-account | grep -q pam_radius"
else
    expect "[tacplus] tacquito's accounting log has alice's session" 'alice' "$(s cat /var/log/tacquito/accounting.log 2> /dev/null)"
fi

if [[ "$CYCLE" == "switch" ]]; then
    section "switch: tacplus -> radius"
    enroll radius; check "host enroll --method radius on the enrolled host exits 0" test $? -eq 0
    note "installed by the switch: $(pkg_versions)"
    check "tacctl said it switches, and the host said what it removed" grep -q "Switching c1 from tacplus to radius" "${WORK}/enroll.out"
    check "the host reports the tacplus leftovers removed" grep -q "This host used tacplus before" "${WORK}/enroll.out"
    where_secret radius
    check "[radius] the accounts are renamed" c bash -c "[[ \$(getent passwd alice | cut -d: -f5) == 'alice (RADIUS)' ]]"
    before=$(radius_log | grep -c 'Access-Accept.*user=alice')
    basic_cases radius
    check "[radius] those logins were answered by FreeRADIUS" test "$(( $(radius_log | grep -c 'Access-Accept.*user=alice') - before ))" -ge 2
    expect "[radius] carl still logs in with his local password while the server is unreachable" '^carl$' "$(block > /dev/null; login carl "$CL_PW" 'id -un'; unblock > /dev/null)"

    section "switch: radius -> tacplus"
    enroll tacplus; check "host enroll --method tacplus exits 0" test $? -eq 0
    check "tacctl said it switches, and the host said what it removed" bash -c "grep -q 'Switching c1 from radius to tacplus' '${WORK}/enroll.out' && grep -q 'This host used radius before' '${WORK}/enroll.out'"
    where_secret tacplus
    check "[tacplus] the accounts are renamed back" c bash -c "[[ \$(getent passwd alice | cut -d: -f5) == 'alice (TACACS+)' ]]"
    before=$(radius_log | grep -c 'user=alice')
    basic_cases tacplus
    check "[tacplus] FreeRADIUS saw none of those logins" test "$(radius_log | grep -c 'user=alice')" -eq "$before"
fi

section "unenroll"
host_secret > "${WORK}/secret"
tacctl host unenroll c1 > "${WORK}/unenroll.out"; rc=$?
sed 's/^/    | /' "${WORK}/unenroll.out" | grep -E 'INFO|WARN|ERROR'
check "host unenroll exits 0" test $rc -eq 0
snapshot > "${WORK}/after"
if diff "${WORK}/before" "${WORK}/after" > "${WORK}/diff"; then
    ok "PAM files, sudoers and module directory are as before the enroll (byte for byte)"
else
    bad "the host differs from before the enroll:"; cat "${WORK}/diff"
fi
check "no secret file, no tacctl PAM file, no method file" c bash -c '[[ ! -e /etc/tacctl-pam_radius.conf && ! -e /etc/pam.d/tacctl-auth && ! -e /var/lib/tacctl-client/method && ! -e /var/lib/tacctl-client/installed ]]'
check "the secret is nowhere on the host" c bash -c "! grep -rqF '$(cat "${WORK}/secret")' /etc /var/lib/tacctl-client"
expect "alice can no longer log in" 'rc=255' "$(login alice "$A_PW" true)"
expect "carl's local account still works" '^carl$' "$(login carl "$CL_PW" 'id -un')"
expect "ladm logs in and can sudo" '^0$' "$(login ladm "$L_PW" "printf '%s\n' '$L_PW' | sudo -S -k -p '' id -u")"
check "the registry is empty" bash -c "[[ -z \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" ]]"
note "left on the host by design: accounts and groups ($(c bash -c 'getent group tac-users | cut -d: -f4')), /var/lib/tacctl-client ($(c ls /var/lib/tacctl-client | paste -sd' ')), packages ($(pkg_versions))"

echo
echo "${CLIENT} ${CYCLE} (server ${SERVER}): ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
