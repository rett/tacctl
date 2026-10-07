#!/bin/bash
# Run the RADIUS container check against real FreeRADIUS (rootless podman).
#
#   tests/containers/radius/run.sh <ubuntu-noble|almalinux-9|almalinux-8> [--keep]
#
# ubuntu-noble, almalinux-9: a systemd container with this checkout mounted
#   read-only; flow.sh runs 'tacctl backend enable radius' and everything
#   after it for real.
# almalinux-8: tacctl is not run in the container; the files are rendered
#   here for the RHEL layout ('tacctl config render --dry-run --out'), copied
#   in, checked with 'radiusd -C' and served by 'radiusd -n tacctl-radius'
#   started by hand; then cases.sh.
#
# Nothing on this machine is touched outside podman and a temp directory.
# Images are built once (tacctl-radius-check:<distro>) and kept; the
# container is removed unless --keep is given. Needs Go in /usr/local/go (the
# binary is built here from this checkout) and python3-bcrypt (make-store.py).
set -euo pipefail
DISTRO="${1:?usage: run.sh <ubuntu-noble|almalinux-9|almalinux-8> [--keep]}"
KEEP="${2:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "${HERE}/../../.." && pwd)"
NAME="tacctl-radius-check-${DISTRO}"
IMAGE="localhost/tacctl-radius-check:${DISTRO}"
WORK=$(mktemp -d)
cleanup() {
    [[ "$KEEP" == "--keep" ]] || podman rm -f -t 0 "$NAME" > /dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
chmod 755 "$WORK"
"${HERE}/make-store.py" "${WORK}/data"
chmod -R a+rX "${WORK}/data"

case "$DISTRO" in
    ubuntu-noble) BASE=docker.io/library/ubuntu:noble
        SETUP='export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus python3 python3-yaml python3-bcrypt iproute2 procps logrotate git diffutils > /dev/null' ;;
    almalinux-9) BASE=docker.io/library/almalinux:9
        SETUP='dnf install -y -q systemd python3 python3-pyyaml python3-pip iproute procps-ng logrotate git findutils diffutils > /dev/null && pip3 install -q bcrypt' ;;
    almalinux-8) BASE=docker.io/library/almalinux:8
        SETUP='dnf install -y -q freeradius freeradius-utils iproute procps-ng > /dev/null' ;;
    *) echo "unknown distro: ${DISTRO}" >&2; exit 2 ;;
esac

if ! podman image exists "$IMAGE"; then
    echo "--- building ${IMAGE} from ${BASE}"
    podman rm -f -t 0 "${NAME}-build" > /dev/null 2>&1 || true
    podman run -d --name "${NAME}-build" "$BASE" sleep infinity > /dev/null
    podman exec "${NAME}-build" bash -c "$SETUP"
    podman commit -q "${NAME}-build" "$IMAGE" > /dev/null
    podman rm -f -t 0 "${NAME}-build" > /dev/null
fi
podman rm -f -t 0 "$NAME" > /dev/null 2>&1 || true

if [[ "$DISTRO" != "almalinux-8" ]]; then
    # SYS_ADMIN: the Debian unit's sandboxing (ProtectKernelTunables and the
    # like) needs it inside a rootless container; a real host does not.
    podman run -d --name "$NAME" --systemd=always --cap-add SYS_ADMIN \
        -v "${REPO}:/opt/tacctl:ro" -v "${WORK}/data:/data:ro" "$IMAGE" /sbin/init > /dev/null
    sleep 4
    podman exec "$NAME" /opt/tacctl/tests/containers/radius/flow.sh /data
    exit $?
fi

# almalinux-8: render here, serve there.
STATE="${WORK}/state"
mkdir -p "$STATE" "${WORK}/out"
podman run -d --name "$NAME" -v "${HERE}:/check:ro" -v "${WORK}/data:/data:ro" "$IMAGE" sleep infinity > /dev/null
MYIP=$(podman exec "$NAME" hostname -I | cut -d' ' -f1)
sed "s#10.0.2.0/24#${MYIP%.*}.0/24#" "${WORK}/data/store.yaml" > "${STATE}/store.yaml"
"${REPO}/bin/tacctl.sh" --build "${WORK}/tacctl" > /dev/null
{ printf 'backends:\n  enabled: [radius]\nlisteners:\n  radius:\n    auth6: {network: udp6, address: "[::]:1812"}\n'
  cat "${WORK}/data/tacctl.yaml"; } > "${STATE}/tacctl.yaml"
(
    export TACCTL_STATE_DIR="$STATE" TACCTL_ETC="${WORK}/etc" TACCTL_LOG="${WORK}/log" TACCTL_SKIP_SUDO=1
    export TACCTL_RADIUS_FAMILY=rhel
    unset TACCTL_RADIUS_DIR TACCTL_RADIUS_LOG TACCTL_RADIUS_BIN
    # The artifacts land under ${WORK}/out at the paths they have on the
    # server (etc/raddb/...); nothing live is touched.
    "${WORK}/tacctl" config render --dry-run --out "${WORK}/out" > /dev/null
)
podman cp "${WORK}/out/etc/raddb/tacctl-radius.conf" "${NAME}:/etc/raddb/tacctl-radius.conf"
podman cp "${WORK}/out/etc/raddb/tacctl-radius.users" "${NAME}:/etc/raddb/tacctl-radius.users"
podman exec "$NAME" mkdir -p /etc/raddb/tacctl-radius-dictionary
podman cp "${WORK}/out/etc/raddb/tacctl-radius-dictionary/dictionary" "${NAME}:/etc/raddb/tacctl-radius-dictionary/dictionary"
podman exec "$NAME" bash -c '
    rpm -q freeradius libxcrypt; radiusd -v | head -1
    chown -R root:radiusd /etc/raddb/tacctl-radius*; chmod 640 /etc/raddb/tacctl-radius.* /etc/raddb/tacctl-radius-dictionary/dictionary
    chmod 750 /etc/raddb/tacctl-radius-dictionary
    radiusd -C -lstdout -d /etc/raddb -D /etc/raddb/tacctl-radius-dictionary -n tacctl-radius | tail -1
    radiusd -d /etc/raddb -D /etc/raddb/tacctl-radius-dictionary -n tacctl-radius; sleep 2
    ps -o user=,args= -C radiusd
    /check/cases.sh /data'
