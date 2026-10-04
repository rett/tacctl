#!/bin/bash
# Build localhost/tacctl-rehearsal:noble: ubuntu:noble with systemd and what
# a server has before tacctl (bash-completion, man-db) plus 0.1.17's
# packages, so the rehearsal does not wait on apt for them.
set -euo pipefail
IMAGE=localhost/tacctl-rehearsal:noble
podman image exists "$IMAGE" && { echo "image exists"; exit 0; }
podman rm -f -t 0 tacctl-rehearsal-build > /dev/null 2>&1 || true
podman run -d --name tacctl-rehearsal-build docker.io/library/ubuntu:noble sleep infinity > /dev/null
podman exec tacctl-rehearsal-build bash -c 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq systemd systemd-sysv dbus git wget ca-certificates sudo iproute2 procps logrotate bash-completion man-db python3 python3-yaml python3-bcrypt openssh-client autoconf automake libtool gnulib gcc make libpam0g-dev podman uidmap > /dev/null && ls -ld /etc/bash_completion.d'
podman commit -q tacctl-rehearsal-build "$IMAGE" > /dev/null
podman rm -f -t 0 tacctl-rehearsal-build > /dev/null
echo built
