#!/bin/bash
# The whole Linux-host matrix recorded in docs/radius-notes.md, one run.sh
# after another (they share the container names, so not in parallel):
#
#   tests/containers/hosts/matrix.sh [<log dir>]
#
# Each run's output goes to <log dir>/<client>.<cycle>[.<server>].log
# (default: a temp directory, printed); the last line of each is repeated
# here. Exit 0 when every run passed. About an hour and a half with the images built.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LOGS="${1:-$(mktemp -d)}"
mkdir -p "$LOGS"
echo "logs: ${LOGS}"
failed=0
run() { # <client> <cycle> [<server>]
    local log="${LOGS}/$1.$2${3:+.$3}.log"
    if "${HERE}/run.sh" "$1" "$2" ${3:+--server "$3"} > "$log" 2>&1; then
        if [[ "$2" == "probe" ]]; then echo "$1 probe: see ${log}"; else tail -1 "$log"; fi
    else
        failed=1
        echo "FAILED: $1 $2 ${3:-}  ($(grep -c '^FAIL' "$log") FAIL lines; see ${log})"
    fi
}
for client in ubuntu-noble debian-trixie debian-bookworm almalinux-8 almalinux-9 almalinux-10 rocky-8 rocky-9 rocky-10; do
    run "$client" radius
done
# What pam_radius_auth returns, per packaged version (read the logs).
for client in ubuntu-noble debian-trixie debian-bookworm almalinux-8 almalinux-9 almalinux-10; do
    run "$client" probe
done
# The same control lines against FreeRADIUS 3.0.27 (EL9's).
run almalinux-9 radius almalinux-9
run ubuntu-noble radius almalinux-9
# TACACS+ has not changed, and switching works both ways.
for client in ubuntu-noble debian-trixie rocky-9 almalinux-10; do
    run "$client" tacplus
done
for client in ubuntu-noble debian-bookworm rocky-8 rocky-9 almalinux-10; do
    run "$client" switch
done
# Rotating the provisioning account: create, prove, sync through it, remove the old one.
for client in ubuntu-noble almalinux-9; do
    run "$client" rotate
done
# The engineer tier: the server's own checks.
run ubuntu-noble server
exit "$failed"
