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
#              rotate   enroll with --method radius, then 'host provisioner
#                       rotate' (--key): create, prove, host sync through the
#                       new account, --remove-old, adoption, a failed proof;
#                       then unenroll
#              server   no enroll of the client: the baseline command rules of
#                       the four roles asked of the real tacquito
#                       (tests/tools/permcheck.py), then this server enrolled
#                       as a host itself ('host enroll --local'): the engineer
#                       tier's group, no %tac-engineer sudoers line here, and
#                       sshd's drop-ins under 'sshd -T'
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
CLIENT="${1:?usage: run.sh <client> <radius|tacplus|switch|probe|rotate|server> [--server <distro>] [--keep]}"
CYCLE="${2:?usage: run.sh <client> <radius|tacplus|switch|probe|rotate|server> [--server <distro>] [--keep]}"
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
    radius|probe|rotate) WANT=radius ;;
    tacplus|server) WANT=tacplus ;;
    switch) WANT=both ;;
    *) echo "unknown cycle: ${CYCLE}" >&2; exit 2 ;;
esac
case "$SERVER" in
    ubuntu-noble) SBASE=docker.io/library/ubuntu:noble
        SSETUP='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus sudo python3 python3-yaml python3-bcrypt iproute2 procps logrotate git diffutils openssh-client nftables autoconf automake libtool gnulib libpam0g-dev build-essential wget ca-certificates > /dev/null' ;;
    almalinux-9) SBASE=docker.io/library/almalinux:9
        [[ "$WANT" == "radius" ]] || { echo "--server almalinux-9 runs the radius and probe cycles only" >&2; exit 2; }
        SSETUP='dnf install -y -q systemd sudo python3 python3-pyyaml python3-pip iproute procps-ng logrotate git findutils diffutils openssh-clients nftables wget > /dev/null && pip3 install -q bcrypt' ;;
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
# The client's IDs: rootless podman has 65536 subordinate IDs to give, and
# the default map (0-65535) leaves out tacctl's 80000-89999. This one keeps
# 0-49999 (the system's accounts, useradd's range and tacctl's earlier
# 20000-29999), 65534-65541 (nobody/nogroup, sshd's privilege separation, and
# the numbers shadow-utils' useradd picks above them when asked for an account
# below 80000: AlmaLinux gave the provisioning account 65536, which a map that
# stops at 65535 cannot own) and maps 80000-89999 too.
CLIENT_IDMAP=()
for m in 0:1:50000 65534:50001:8 80000:50009:10000; do CLIENT_IDMAP+=(--uidmap "$m" --gidmap "$m"); done
podman run -d --name "$C" --network "$NET" --cap-add AUDIT_WRITE "${CLIENT_IDMAP[@]}" -v "${HERE}:/check:ro" \
    "$CIMAGE" /usr/sbin/sshd -D -e > /dev/null || exit 1
sleep 4
# visudo: tacctl checks every sudoers line it writes with it ('config linux
# engineer-sudo'), as on any server that has sudo. Server images built before
# it was in the package list get it now.
s bash -c 'command -v visudo > /dev/null || { if command -v apt-get > /dev/null; then apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo; else dnf install -y -q sudo; fi; } > /dev/null 2>&1'
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

# --- server: what only the server container can show ------------------------------
# No enrollment of the client: the real tacquito answers authorization
# requests for the baseline command rules of the four roles
# (tests/tools/permcheck.py and permcheck-baseline.txt), and this server is
# enrolled as a host itself ('host enroll --local'): the engineer tier's
# group number, its sudoers line (none here), and sshd's drop-ins.
if [[ "$CYCLE" == "server" ]]; then
    section "server: the role preset, four lab users and the baseline rules asked of the real tacquito"
    printf 'y\n' | podman exec -i "$S" tacctl group preset roles 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'applied|Nothing|ERROR' | head -3
    PC_SECRET='permcheck-secret-0123456789'
    tacctl scope add permlab --prefixes "${SIP}/32,127.0.0.1/32" --secret "$PC_SECRET" --protocols tacacs > /dev/null
    pchash=$(s python3 -c 'import bcrypt; print(bcrypt.hashpw(b"Gotest-Net-Pw-1", bcrypt.gensalt(rounds=10)).decode())')
    for pair in gotestviewer:readonly gotestoperator:operator gotestengineer:engineer gotestsuper:superuser; do
        tacctl user add "${pair%%:*}" "${pair##*:}" --hash "$pchash" --scopes permlab > /dev/null
    done
    tacctl config render > /dev/null 2>&1
    check "tacquito is active after the changes" s systemctl is-active --quiet tacquito
    for pair in gotestviewer:readonly gotestoperator:operator gotestengineer:engineer gotestsuper:superuser; do
        expect "${pair%%:*} is in group ${pair##*:}" "${pair%%:*} +[^ ]+ +${pair##*:} " "$(tacctl user list)"
    done
    s python3 /opt/tacctl/tests/tools/permcheck.py --host "$SIP" --port 49 --secret "$PC_SECRET" /opt/tacctl/tests/tools/permcheck-baseline.txt > "${WORK}/permcheck.out" 2>&1; rc=$?
    tail -5 "${WORK}/permcheck.out"
    grep -vE '^(ok|PASS)' "${WORK}/permcheck.out" | head -30
    check "permcheck: every baseline pair got the expected answer from the real tacquito ($(grep -cE '^[a-z]' "${REPO}/tests/tools/permcheck-baseline.txt") pairs)" test $rc -eq 0
    # The three commands by name, for each role, with the answer printed.
    printf '%s\n' 'gotestviewer|show|version|permit' 'gotestoperator|show|version|permit' 'gotestengineer|show|version|permit' 'gotestsuper|show|version|permit' \
        'gotestviewer|show|running-config|permit' 'gotestoperator|show|running-config|permit' 'gotestengineer|show|running-config|permit' \
        'gotestviewer|no|aaa new-model|deny' 'gotestoperator|no|aaa new-model|deny' 'gotestengineer|no|aaa new-model|permit' > "${WORK}/three.txt"
    podman cp "${WORK}/three.txt" "${S}:/root/three.txt"
    s python3 /opt/tacctl/tests/tools/permcheck.py --host "$SIP" --port 49 --secret "$PC_SECRET" /root/three.txt > "${WORK}/three.out" 2>&1; rc=$?
    tail -12 "${WORK}/three.out"
    check "show version, show running-config and no aaa new-model per role are answered as the baseline says" test $rc -eq 0
    log=$(s journalctl -u tacquito --no-pager -n 40 2> /dev/null | grep -ciE 'regexp|regex|panic|invalid' || true)
    note "tacquito's journal lines about regex/panic/invalid: ${log}"

    section "server: this server enrolled as a host ('host enroll --local'): engineer group number, sudoers, sshd drop-ins"
    c_ssh=$(s bash -c 'DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server > /dev/null 2>&1; mkdir -p /run/sshd; command -v sshd')
    note "sshd on the server container: ${c_ssh:-absent}"
    # sshd must be running for tacctl to reload it (the container's ssh.socket starts it on demand only).
    s bash -c 'ln -sf /usr/local/bin/tacctl /usr/local/bin/tacctl-console 2> /dev/null; systemctl start ssh.service' > /dev/null 2>&1
    # The server container's user namespace holds UIDs up to 65536, not tacctl's 80000-89999: its own range.
    tacctl config linux uid-range 50000-59999 > /dev/null
    # enroll wants a local administrator with a password (the lockout check).
    s bash -c 'useradd -m -s /bin/bash -G sudo ladm && echo ladm:Local-Admin-Pw-1 | chpasswd'
    tacctl host enroll --local --name srv --method tacplus --scope permlab > "${WORK}/local.out" 2>&1; rc=$?
    sed 's/\x1b\[[0-9;]*m//g' "${WORK}/local.out" | grep -E 'INFO|WARN|ERROR|Installed|Updated' | head -20 | sed 's/^/    | /'
    check "host enroll --local exits 0" test $rc -eq 0
    check "tac-engineer is GID 50005 here too (first + 5), tac-users 50000, tac-superuser 50002" s bash -c "[[ \$(getent group tac-engineer | cut -d: -f3) == 50005 && \$(getent group tac-users | cut -d: -f3) == 50000 && \$(getent group tac-superuser | cut -d: -f3) == 50002 ]]"
    check "the engineer account is in tac-engineer and not in tac-superuser; the superuser the other way" s bash -c 'id -nG gotestengineer | grep -qw tac-engineer && ! id -nG gotestengineer | grep -qw tac-superuser && id -nG gotestsuper | grep -qw tac-superuser'
    note "this server's sudoers drop-in: $(s bash -c 'grep -hv "^#" /etc/sudoers.d/tacctl-host 2> /dev/null | grep -v "^$" | paste -sd"|"')"
    check "TAC_LOCAL: no %tac-engineer ALL line on the server itself (engineers have tacctl's own sudo rows only)" s bash -c '! grep -qs "^%tac-engineer ALL=(ALL:ALL) ALL" /etc/sudoers.d/tacctl-host'
    ls_out=$(s ls /etc/ssh/sshd_config.d); note "sshd_config.d: $(tr '\n' ' ' <<< "$ls_out")"
    check "the engineers' sshd drop-in exists and sorts before the console's" s bash -c 'cd /etc/ssh/sshd_config.d && [[ -f 00-tacctl-engineer.conf && $(ls | sort | head -1) == 00-tacctl-engineer.conf ]] && [[ 00-tacctl-engineer.conf < tacctl-console.conf ]]'
    tacctl console check > "${WORK}/ccheck.out" 2>&1; rc=$?
    sed 's/\x1b\[[0-9;]*m//g' "${WORK}/ccheck.out" | tail -12 | sed 's/^/    | /'
    check "tacctl console check on the enrolled server: sshd applies the console's and the engineers' settings (exit 0)" test $rc -eq 0
    # An engineer who is also, through a stale membership, in tac-superuser and
    # tac-console: the first value of each keyword wins across the files, in name order.
    s bash -c 'useradd -M -s /bin/bash -G tac-engineer,tac-superuser,tac-console both1 && useradd -M -s /bin/bash -G tac-superuser,tac-console sup1' || bad "could not make the two accounts with the tacctl groups"
    s tacctl console forwarding tiers superuser > /dev/null 2>&1
    tacctl console install > "${WORK}/cinst.out" 2>&1; sed 's/\x1b\[[0-9;]*m//g' "${WORK}/cinst.out" | tail -4 | sed 's/^/    | /'
    for k in allowtcpforwarding x11forwarding allowstreamlocalforwarding permittunnel gatewayports; do
        expect "sshd -T: an engineer who is also in tac-superuser and tac-console: ${k} no" "^${k} no\$" "$(s sshd -T -C user=both1,host=localhost,addr=127.0.0.1 2>&1 | grep -i "^${k} ")"
    done
    expect "sshd -T: that account runs the console (ForceCommand)" '^forcecommand /usr/local/bin/tacctl-console' "$(s sshd -T -C user=both1,host=localhost,addr=127.0.0.1 2>&1 | grep -i '^forcecommand')"
    expect "sshd -T: a superuser with the console (forwarding tier) may forward TCP" '^allowtcpforwarding yes' "$(s sshd -T -C user=sup1,host=localhost,addr=127.0.0.1 2>&1 | grep -i '^allowtcpforwarding')"
    tacctl console check > "${WORK}/ccheck2.out" 2>&1; rc=$?
    expect "tacctl console check finds the two hand-made accounts: stale tac-superuser membership, an engineer with a shell (exit non-zero)" 'both1: still in tac-superuser.*(stale membership|login shell)|stale membership' "$(sed 's/\x1b\[[0-9;]*m//g' "${WORK}/ccheck2.out" | tr '\n' ' ')"
    check "and its exit status is 1" test $rc -eq 1

    echo
    echo "${CLIENT} ${CYCLE} (server ${SERVER}): ${pass} passed, ${fail} failed"
    [[ $fail -eq 0 ]]
    exit $?
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
    c bash -c 'echo note > ~bob/note && chown bob: ~bob/note && touch ~ladm/keepme && chown ladm: ~ladm/keepme && ln -s ~ladm/keepme ~bob/lnk && chown -h bob: ~bob/lnk'
    tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
    check "[$m] host sync succeeds and deletes bob's account (userdel), with his group" bash -c "[[ $rc == 0 ]] && grep -q \"Deleted account 'bob'\" '${WORK}/sync.out' && ! podman exec '$C' id bob && ! podman exec '$C' getent group bob"
    check "[$m] no terminal and no --remove-home: bob's home is kept, moved out of /home and reported" bash -c "grep -q 'home kept: /home/.tacctl-removed/bob-[0-9]\{8\}-[0-9]\{6\}' '${WORK}/sync.out' && ! podman exec '$C' test -e /home/bob"
    moved=$(c bash -c 'ls -d /home/.tacctl-removed/bob-*' | head -1)
    expect "[$m] /home/.tacctl-removed is root's, 0700" '^root:root 700$' "$(c stat -c '%U:%G %a' /home/.tacctl-removed)"
    expect "[$m] bob's moved home is root's, 0700" '^root:root 700$' "$(c stat -c '%U:%G %a' "$moved")"
    expect "[$m] the files in it are root's" '^root:root$' "$(c stat -c '%U:%G' "${moved}/note")"
    check "[$m] the link in it is still a link (made root's itself), and what it points to is untouched" bash -c "[[ \$(podman exec '$C' stat -c '%U %F' '${moved}/lnk') == 'root symbolic link' && \$(podman exec '$C' bash -c 'stat -c %U ~ladm/keepme') == ladm ]]"
    # A local account later given bob's old UID (useradd may hand out a
    # number of the range) gets nothing of his.
    bob_uid=$(s sed -n 's/^bob://p' /etc/tacctl/linux-uids)
    c useradd -m -u "$bob_uid" newbob > /dev/null 2>&1
    check "[$m] a local account with bob's old UID ${bob_uid} cannot read his kept home" bash -c "! podman exec '$C' runuser -u newbob -- ls '${moved}'"
    c userdel -r newbob > /dev/null 2>&1
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
        check "[$m] erin's UID stays reserved on the server" bash -c "podman exec '$S' grep -qx 'erin:80004' /etc/tacctl/linux-uids"
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

FIRST="$CYCLE"; [[ "$CYCLE" == "switch" ]] && FIRST="tacplus"; [[ "$CYCLE" == "rotate" ]] && FIRST="radius"

section "before: snapshot, then enroll with --method ${FIRST}"
snapshot > "${WORK}/before"
check "nothing of tacctl on the host yet" c bash -c '[[ ! -e /var/lib/tacctl-client && ! -e /etc/pam.d/tacctl-auth ]]'
# A login.defs whose useradd range reaches tacctl's (the default UID_MAX
# 60000 does not): enroll warns.
c cp /etc/login.defs /root/login.defs.orig
c sed -i 's/^UID_MAX[[:space:]].*/UID_MAX\t\t\t85000/' /etc/login.defs
# The host's own scope (enroll uses the scope covering its address; it
# makes none).
tacctl scope add linux-c1 --prefixes "${CIP}/32" --secret generate --protocols "$([[ $FIRST == radius ]] && echo radius || echo tacacs)" > /dev/null
enroll "$FIRST"; check "host enroll --method ${FIRST} exits 0" test $? -eq 0
[[ "$FIRST" == "radius" ]] && note "installed by the enrollment: $(pkg_versions)"
check "enroll said there are no users in the scope yet" grep -q "No users are in scope 'linux-c1' yet" "${WORK}/enroll.out"
check "enroll warns that the host's login.defs lets useradd give out UIDs of 80000-89999" grep -q "c1: local useradd there gives out UIDs 1000-85000 (/etc/login.defs UID_MIN/UID_MAX), which overlaps tacctl's 80000-89999:" "${WORK}/enroll.out"
check "enroll recorded the address its ssh connection reached" bash -c "podman exec '$S' grep -A1 '^  c1:' /etc/tacctl/devices.yaml | grep -qF 'address: ${CIP}'"
expect "device show finds the host by that address" "Enrolled host c1" "$(tacctl device show "$CIP")"
expect "device add refuses that address" "${CIP} belongs to the enrolled host 'c1'." "$(tacctl device add c1copy "$CIP" --no-host-key)"
# The distribution's own login.defs (UID_MAX 60000): no warning on the next
# sync, and local useradd stays below the range.
c cp /root/login.defs.orig /etc/login.defs

# --- rotate: the provisioning account ('host provisioner rotate') ---------------
# tacctl logs in to the client as root here, so the first rotation leaves root
# (not removed: --remove-old refuses root); the second one removes the account
# the first made, over the new one. The key is made by ssh-keygen in the server
# container, where tacctl runs as root: every access to it is root's own.
if [[ "$CYCLE" == "rotate" ]]; then
    section "rotate: dry run, then root -> deploy2 with a key"
    s ssh-keygen -q -t ed25519 -N '' -f /root/rot-key
    reg() { s cat /etc/tacctl/linux-hosts; }
    reg_before=$(reg)
    out=$(tacctl host provisioner c1 rotate deploy2 --key /root/rot-key --dry-run)
    expect "dry run: the plan names the useradd line" "useradd -m -U -s /bin/bash -c 'tacctl provisioning account' -K UID_MAX=79999 -K GID_MAX=79999 deploy2" "$out"
    expect "dry run: reads the host's sshd setting" 'sshd on c1: passwordauthentication' "$out"
    expect "dry run: changes nothing" 'Dry run: nothing was changed.' "$out"
    check "dry run: no account on the host, the registry unchanged" bash -c "! podman exec '$C' id deploy2 && [[ \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" == '${reg_before}' ]]"

    tacctl host provisioner c1 rotate deploy2 --key /root/rot-key --yes > "${WORK}/rot1.out"; rc=$?
    sed 's/^/    | /' "${WORK}/rot1.out" | grep -E 'INFO|WARN|ERROR'
    check "rotate root -> deploy2 exits 0" test $rc -eq 0
    check "the registry reaches the client as deploy2 with the key" bash -c "[[ \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" == *'|deploy2@${CIP}||linux-c1|'*'|/root/rot-key|radius' ]]"
    check "the account carries the marker comment and a UID and GID below tacctl's range" c bash -c "[[ \$(getent passwd deploy2 | cut -d: -f5) == 'tacctl provisioning account' ]] && (( \$(id -u deploy2) < 80000 && \$(id -g deploy2) < 80000 ))"
    check "root's record of the account is in a root-only directory (0700, 0600) with its name and UID" c bash -c "[[ \$(stat -c '%a %U' /var/lib/tacctl-provisioner) == '700 root' && \$(stat -c '%a %U' /var/lib/tacctl-provisioner/deploy2) == '600 root' ]] && grep -qx 'account=deploy2' /var/lib/tacctl-provisioner/deploy2 && grep -qx \"uid=\$(id -u deploy2)\" /var/lib/tacctl-provisioner/deploy2 && grep -qx 'ssh_dir=1' /var/lib/tacctl-provisioner/deploy2"
    check "its password is locked and its sudoers line is NOPASSWD: ALL, in its own file (visudo -c is happy)" c bash -c "getent shadow deploy2 | cut -d: -f2 | grep -q '^!' && grep -qx 'deploy2 ALL=(ALL:ALL) NOPASSWD: ALL' /etc/sudoers.d/tacctl-provisioner && [[ \$(stat -c %a /etc/sudoers.d/tacctl-provisioner) == 440 ]] && visudo -c > /dev/null"
    check "deploy2/.ssh is 0700 and authorized_keys 0600, both deploy2's, one line" c bash -c 'h=$(getent passwd deploy2 | cut -d: -f6); [[ $(stat -c "%a %U" "$h/.ssh") == "700 deploy2" && $(stat -c "%a %U" "$h/.ssh/authorized_keys") == "600 deploy2" && $(wc -l < "$h/.ssh/authorized_keys") == 1 ]]'
    if [[ "$(c bash -c 'cut -d" " -f2 "$(getent passwd deploy2 | cut -d: -f6)/.ssh/authorized_keys"')" == "$(s cut -d' ' -f2 /root/rot-key.pub)" ]]; then ok "authorized_keys holds the key tacctl was given"; else bad "authorized_keys holds another key than tacctl was given"; fi
    if c bash -c 'command -v selinuxenabled > /dev/null && selinuxenabled'; then
        expect "SELinux is on: the .ssh directory and authorized_keys have the ssh_home_t type" 'ssh_home_t' "$(c bash -c 'h=$(getent passwd deploy2 | cut -d: -f6); ls -dZ "$h/.ssh" "$h/.ssh/authorized_keys"')"
    else
        note "SELinux is not enabled in this client container: restorecon's effect is not checked here"
    fi
    check "the old login (root) still works" s ssh -o BatchMode=yes "root@${CIP}" true
    # host sync now goes through deploy2.
    tacctl user scope alice add linux-c1 > /dev/null
    tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
    check "host sync through the new account exits 0 and creates alice" bash -c "[[ $rc == 0 ]] && grep -q 'c1: synced' '${WORK}/sync.out' && podman exec '$C' id alice"
    check "sync left the provisioning account alone (not in tacctl's groups, still below the range)" c bash -c "! id -nG deploy2 | grep -q 'tac-' && (( \$(id -u deploy2) < 80000 ))"

    section "rotate: adoption, a foreign account, a marker without a record, deploy2 -> deploy3 --remove-old"
    # deploy3 is left as an interrupted run would leave it: root's record names it.
    c useradd -m -c 'tacctl provisioning account' deploy3
    c bash -c 'mkdir -p -m 0700 /var/lib/tacctl-provisioner && printf "account=deploy3\nuid=%s\nssh_dir=0\n" "$(id -u deploy3)" > /var/lib/tacctl-provisioner/deploy3 && chmod 0600 /var/lib/tacctl-provisioner/deploy3'
    c useradd -m other1
    # deploy5 only carries the comment: the account can write that itself.
    c useradd -m -c 'tacctl provisioning account' deploy5
    reg_now=$(reg)
    tacctl host provisioner c1 rotate other1 --key /root/rot-key --yes > "${WORK}/rot2.out"; rc=$?
    check "an existing account that is not ours is refused and nothing changes" bash -c "[[ $rc != 0 ]] && grep -q 'is not a tacctl provisioning account' '${WORK}/rot2.out' && [[ \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" == '${reg_now}' ]]"
    tacctl host provisioner c1 rotate deploy5 --key /root/rot-key --yes > "${WORK}/rot2b.out"; rc=$?
    check "an account with only the marker comment is refused: no record of tacctl creating it; no sudoers line, no key" bash -c "[[ $rc != 0 ]] && grep -q 'tacctl has no root-owned record of creating it' '${WORK}/rot2b.out' && ! podman exec '$C' grep -q '^deploy5 ' /etc/sudoers.d/tacctl-provisioner && [[ -z \"\$(podman exec '$C' find /home -maxdepth 2 -name .ssh -path '*deploy5*')\" ]] && [[ \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" == '${reg_now}' ]]"
    tacctl host provisioner c1 rotate deploy3 --key /root/rot-key --remove-old --yes > "${WORK}/rot3.out"; rc=$?
    sed 's/^/    | /' "${WORK}/rot3.out" | grep -E 'INFO|WARN|ERROR'
    check "rotate deploy2 -> deploy3 --remove-old exits 0 and adopts the account that was there" bash -c "[[ $rc == 0 ]] && grep -q \"Adopting the existing provisioning account 'deploy3'\" '${WORK}/rot3.out' && grep -q \"The old account 'deploy2' is removed from c1.\" '${WORK}/rot3.out'"
    check "deploy2 is gone with its group, its record, its home moved out of reach (root's, 0700), its sudoers line removed" c bash -c "! getent passwd deploy2 && ! getent group deploy2 && [[ ! -e /var/lib/tacctl-provisioner/deploy2 ]] && [[ ! -e /home/deploy2 ]] && [[ \$(stat -c %U:%G /home/.tacctl-removed/deploy2-*) == root:root ]] && ! grep -q '^deploy2 ' /etc/sudoers.d/tacctl-provisioner && grep -qx 'deploy3 ALL=(ALL:ALL) NOPASSWD: ALL' /etc/sudoers.d/tacctl-provisioner"
    check "the registry reaches the client as deploy3; alice's account is still there" bash -c "[[ \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" == *'|deploy3@${CIP}||'* ]] && podman exec '$C' id alice"
    tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
    check "host sync through deploy3 exits 0" test $rc -eq 0

    section "rotate: a proof that fails takes the new account away again"
    # sshd refuses public keys for deploy4, so the fresh login fails.
    c bash -c 'printf "%s\n" "Match User deploy4" "    PubkeyAuthentication no" >> /etc/ssh/sshd_config; kill -HUP 1; sleep 1'
    reg_now=$(reg)
    tacctl host provisioner c1 rotate deploy4 --key /root/rot-key --yes > "${WORK}/rot4.out"; rc=$?
    sed 's/^/    | /' "${WORK}/rot4.out" | grep -E 'INFO|WARN|ERROR'
    check "the rotation fails at the proof and says the account was removed" bash -c "[[ $rc != 0 ]] && grep -q 'The proof failed' '${WORK}/rot4.out' && grep -q \"The new account 'deploy4' and its sudoers line were removed from c1\" '${WORK}/rot4.out'"
    check "no deploy4 account, home, record or sudoers line; the registry is unchanged" bash -c "! podman exec '$C' getent passwd deploy4 && ! podman exec '$C' test -e /home/deploy4 && ! podman exec '$C' test -e /var/lib/tacctl-provisioner/deploy4 && ! podman exec '$C' grep -q '^deploy4 ' /etc/sudoers.d/tacctl-provisioner && [[ \"\$(podman exec '$S' cat /etc/tacctl/linux-hosts)\" == '${reg_now}' ]]"
    check "the audit line of the failed step is in the server's log" bash -c "podman exec '$S' journalctl -t tacctl --no-pager | grep -q 'host provisioner rotate name=c1 old=deploy3 new=deploy4 auth=key step=prove'"
    c bash -c 'sed -i "/^Match User deploy4$/,\$d" /etc/ssh/sshd_config; kill -HUP 1; sleep 1'

    section "unenroll through deploy3"
    tacctl host unenroll c1 > "${WORK}/unenroll.out"; rc=$?
    check "host unenroll through the provisioning account exits 0" test $rc -eq 0
    c bash -c 'userdel -r deploy3 2> /dev/null; userdel -r other1 2> /dev/null; userdel -r deploy5 2> /dev/null; rm -f /etc/sudoers.d/tacctl-provisioner /etc/sudoers.d/.tacctl-provisioner.lock; rm -rf /home/.tacctl-removed /var/lib/tacctl-provisioner'
    snapshot > "${WORK}/after"
    if diff "${WORK}/before" "${WORK}/after" > "${WORK}/diff"; then
        ok "PAM files, sudoers and module directory are as before the enroll"
    else
        bad "the host differs from before the enroll:"; cat "${WORK}/diff"
    fi
    echo
    echo "${CLIENT} ${CYCLE} (server ${SERVER}): ${pass} passed, ${fail} failed"
    [[ $fail -eq 0 ]]
    exit $?
fi

section "users: alice (superuser), bob (operator), dave and erin (readonly), carl (readonly; the host has a local carl)"
# carl as an earlier release left an adopted account: in tacctl's groups
# (those a host other than the server has: tac-users, tac-superuser) and
# listed in the 'adopted' state file.
c bash -c 'usermod -aG tac-users,tac-superuser carl && echo carl > /var/lib/tacctl-client/adopted'
carl_before=$(c getent passwd carl); carl_shadow=$(c getent shadow carl); carl_groups=$(c id -nG carl | tr ' ' '\n' | grep -v '^tac-' | sort | paste -sd' ')
for u in alice bob carl dave erin; do tacctl user scope "$u" add linux-c1 > /dev/null; done
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
check "host sync refuses carl (a local account tacctl did not create), goes on, and says so in its summary" bash -c "[[ $rc == 0 ]] && grep -q \"'carl': this host has a local account of that name that tacctl did not create\" '${WORK}/sync.out' && grep -q 'c1: synced (4 users; 1 refused: carl)' '${WORK}/sync.out'"
check "the adopted carl is reported once, taken out of tacctl's groups, and forgotten" bash -c "grep -q 'adopted are no longer tracked: carl' '${WORK}/sync.out' && grep -q \"'carl': removed from tacctl's groups (tac-users, tac-superuser); it is a plain local account again.\" '${WORK}/sync.out' && ! podman exec '$C' test -e /var/lib/tacctl-client/adopted"
check "nothing else of carl's account changed (passwd and shadow lines, other groups)" bash -c "[[ \"\$(podman exec '$C' getent passwd carl)\" == '${carl_before}' && \"\$(podman exec '$C' getent shadow carl)\" == '${carl_shadow}' && \"\$(podman exec '$C' id -nG carl | tr ' ' '\\n' | sort | paste -sd' ')\" == '${carl_groups}' ]]"
check "with the default UID_MAX 60000 the sync does not warn about login.defs" bash -c "! grep -q 'local useradd there' '${WORK}/sync.out'"
c useradd -m localx > /dev/null 2>&1
check "local useradd with the default login.defs gives a UID below 80000" bash -c "id=\$(podman exec '$C' id -u localx) && (( id < 80000 ))"
c userdel -r localx > /dev/null 2>&1
check "every account tacctl created has a UID in 80000-89999" bash -c "for u in alice bob dave erin; do id=\$(podman exec '$C' id -u \$u) && (( id >= 80000 && id <= 89999 )) || exit 1; done"
check "tacctl's groups here are tac-users 80000, tac-superuser 80002 and tac-engineer 80005 only; accounts have tac-users as primary group and a 0700 home" c bash -c "[[ \$(getent group | grep '^tac-' | cut -d: -f1,3 | sort | paste -sd' ') == 'tac-engineer:80005 tac-superuser:80002 tac-users:80000' ]] && for u in alice dave erin; do [[ \$(id -gn \$u) == tac-users && \$(stat -c %a /home/\$u) == 700 ]] || exit 1; done"

section "the engineer tier: bob's group given the tier engineer (D18), then back"
# tier.<group> in tacctl.yaml is what 'tacctl group edit <g> tier' (WP9.4)
# writes; the file is edited here so the case does not depend on it.
expect "bob (operator) may not sudo" 'not (allowed|in the sudoers)|rc=1' "$(login bob "$B_PW" "printf '%s\n' '$B_PW' | sudo -S -k -p '' id -u")"
s bash -c "printf 'tier:\n  operator: engineer\n' >> /etc/tacctl/tacctl.yaml"
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
check "the sync puts bob (engineer) in tac-engineer, not tac-superuser" c bash -c "[[ $rc == 0 ]] && id -nG bob | grep -qw tac-engineer && ! id -nG bob | grep -qw tac-superuser"
check "the host's sudoers drop-in has the tac-engineer line (default: every command)" c grep -qx '%tac-engineer ALL=(ALL:ALL) ALL' /etc/sudoers.d/tacctl-host
expect "bob (engineer) logs in with the network password and sudo gives root (every command)" '^0$' "$(login bob "$B_PW" "printf '%s\n' '$B_PW' | sudo -S -k -p '' id -u")"
tacctl config linux engineer-sudo /usr/bin/systemctl,/usr/bin/journalctl > /dev/null
tacctl host sync c1 > "${WORK}/sync.out"
check "engineer-sudo reaches the host at its next sync, through visudo" bash -c "grep -q 'Sudoers drop-in /etc/sudoers.d/tacctl-host updated (engineers: /usr/bin/systemctl, /usr/bin/journalctl)' '${WORK}/sync.out' && podman exec '$C' grep -qx '%tac-engineer ALL=(ALL:ALL) /usr/bin/systemctl, /usr/bin/journalctl' /etc/sudoers.d/tacctl-host"
expect "bob (engineer, limited): sudo systemctl is allowed" '^systemd [0-9]+' "$(login bob "$B_PW" "printf '%s\n' '$B_PW' | sudo -S -k -p '' /usr/bin/systemctl --version")"
expect "bob (engineer, limited): sudo id is refused" 'not (allowed|in the sudoers)|rc=1|may not run' "$(login bob "$B_PW" "printf '%s\n' '$B_PW' | sudo -S -k -p '' id -u")"
tacctl config linux engineer-sudo all > /dev/null
s sed -i '/^tier:$/,/^  operator: engineer$/d' /etc/tacctl/tacctl.yaml
tacctl host sync c1 > "${WORK}/sync.out"
check "back to operator: bob leaves tac-engineer; the drop-in is every command again" c bash -c "! id -nG bob | grep -qw tac-engineer && grep -qx '%tac-engineer ALL=(ALL:ALL) ALL' /etc/sudoers.d/tacctl-host"
LABEL="TACACS+"; [[ "$FIRST" == "radius" ]] && LABEL="RADIUS"
check "alice's account: UID 80000, locked password, named 'alice (${LABEL})'" c bash -c "[[ \$(id -u alice) == 80000 && \$(getent passwd alice | cut -d: -f5) == 'alice (${LABEL})' ]] && getent shadow alice | cut -d: -f2 | grep -q '^!'"

section "renumbering: dave as an earlier release left him (UID and map entry in 20000-29999)"
# The host's account at the legacy number tacctl gave out before (state
# 'created', an own group named like it with that number as its primary
# group, home owned by it), a file outside the home with that number, and
# the server's map entry at the legacy number. The sync renumbers the UID
# and, as for every account of an earlier release, makes tac-users its
# primary group and removes the own group (item 62).
dave_new=$(s sed -n 's/^dave://p' /etc/tacctl/linux-uids)
dave_old=$((dave_new - 60000))
users_gid=$(c getent group tac-users | cut -d: -f3)
c bash -c "groupadd -g ${dave_old} dave && usermod -u ${dave_old} -g dave dave > /dev/null
    chown -R ${dave_old}:${dave_old} ~dave && echo note > ~dave/note && chown ${dave_old}:${dave_old} ~dave/note
    echo x > /var/tmp/dave-stray && chown ${dave_old}:${dave_old} /var/tmp/dave-stray"
# The map as 0.2.0 left it: no '# range' record (0.2.1 item 52 adds it),
# so the entry at a legacy number is renumbered, not taken for one outside
# the range.
s sed -i -e '/^#/d' -e "s/^dave:${dave_new}\$/dave:${dave_old}/" /etc/tacctl/linux-uids
check "dave starts at UID/GID ${dave_old}, the map at ${dave_old}" bash -c "[[ \$(podman exec '$C' id -u dave) == ${dave_old} && \$(podman exec '$C' id -g dave) == ${dave_old} ]] && podman exec '$S' grep -qx 'dave:${dave_old}' /etc/tacctl/linux-uids"
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
sed 's/^/    | /' "${WORK}/sync.out" | grep -iE 'renumber|stray|carry'
check "the sync renumbers the server's map once, keeps the old one and logs it" bash -c "[[ $rc == 0 ]] && grep -q 'Renumbered 1 entry of /etc/tacctl/linux-uids from 20000-29999 to 80000-89999' '${WORK}/sync.out' && podman exec '$S' grep -qx 'dave:${dave_new}' /etc/tacctl/linux-uids && podman exec '$S' bash -c 'grep -qx dave:${dave_old} /etc/tacctl/linux-uids.pre-renumber-*' && podman exec '$S' journalctl -t tacctl --no-pager | grep -q 'uid-map renumbered 1 entries'"
check "the host renumbers dave ${dave_old} -> ${dave_new} and the summary counts it" bash -c "grep -q \"'dave': renumbered ${dave_old} -> ${dave_new} (home re-owned)\" '${WORK}/sync.out' && grep -q 'c1: synced (4 users; 1 renumbered; 1 refused: carl)' '${WORK}/sync.out'"
check "dave's UID is ${dave_new}, his primary group tac-users (${users_gid}), his own group gone" c bash -c "[[ \$(id -u dave) == ${dave_new} && \$(id -g dave) == ${users_gid} ]] && ! getent group dave > /dev/null"
check "dave's home and the files in it are ${dave_new}:${users_gid}, the home 0700" c bash -c "[[ \$(stat -c %u:%g ~dave) == ${dave_new}:${users_gid} && \$(stat -c %u:%g ~dave/note) == ${dave_new}:${users_gid} && \$(stat -c %a ~dave) == 700 ]]"
check "the stray file outside the home is reported and left as it was" bash -c "grep -q '/var/tmp/dave-stray' '${WORK}/sync.out' && [[ \$(podman exec '$C' stat -c %u:%g /var/tmp/dave-stray) == ${dave_old}:${dave_old} ]]"
c rm -f /var/tmp/dave-stray
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
check "a second sync renumbers nothing" bash -c "[[ $rc == 0 ]] && ! grep -qi 'renumbered' '${WORK}/sync.out' && grep -q 'c1: synced (4 users; 1 refused: carl)' '${WORK}/sync.out'"

section "tac-users: erin as 0.2.0 left her (listed in it as a supplementary group as well)"
# 0.2.0 put every account in tac-users as a supplementary group; 0.2.1 made
# it the primary group and kept that entry. The sync takes the entry out.
c gpasswd -a erin tac-users > /dev/null
check "erin starts listed in tac-users" c bash -c "getent group tac-users | cut -d: -f4 | tr ',' '\\n' | grep -qx erin"
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
check "the sync takes erin out of tac-users' member list and says so" bash -c "[[ $rc == 0 ]] && grep -q \"'erin': no longer listed in tac-users as a supplementary group (it is the primary group).\" '${WORK}/sync.out'"
check "tac-users lists no members; tac-users is still every account's primary group" c bash -c "[[ -z \$(getent group tac-users | cut -d: -f4) ]] && for u in alice dave erin; do [[ \$(id -gn \$u) == tac-users ]] || exit 1; done"
tacctl host sync c1 > "${WORK}/sync.out"; rc=$?
check "a second sync has nothing to change" bash -c "[[ $rc == 0 ]] && ! grep -q 'supplementary' '${WORK}/sync.out'"

section "cases (${FIRST})"
where_secret "$FIRST"
full_cases "$FIRST"
if [[ "$FIRST" == "radius" ]]; then
    # The host names itself as the NAS (client_id=, its FQDN; 0.2.1 item
    # 61), never the PAM service (sshd, sudo) pam_radius_auth sends without it.
    cname=$(c bash -c 'hostname -f 2> /dev/null || hostname')
    expect "[radius] the server's auth log has alice's accepts from this host, named by its hostname (${cname})" "Access-Accept scope=linux-c1 device=generic client=${CIP} nas=${cname} .*user=alice" "$(radius_log)"
    if radius_log | grep -qE 'nas=(sshd|sudo|sudo-i|login|gdm-password) '; then bad "[radius] a record names a PAM service as the NAS"; else ok "[radius] no record names a PAM service as the NAS"; fi
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
note "left on the host by design: accounts and groups ($(c bash -c 'g=$(getent group tac-users | cut -d: -f3); getent passwd | awk -F: -v g="$g" '"'"'$4 == g { print $1 }'"'"' | paste -sd,')), /var/lib/tacctl-client ($(c ls /var/lib/tacctl-client | paste -sd' ')), packages ($(pkg_versions))"

echo
echo "${CLIENT} ${CYCLE} (server ${SERVER}): ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
