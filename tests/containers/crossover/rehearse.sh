#!/bin/bash
# WP3.3d container rehearsal of the bash -> Go cross-over (rootless podman,
# local containers only; nothing on this host is touched outside podman and
# this directory).
#
#   rehearse.sh install            0.1.17 from the tag via the README one-liner,
#                                  committed as localhost/tacctl-rehearsal:installed-0.1.17
#   rehearse.sh fresh              0.2.0 from scratch: the shim of go-rehearsal
#                                  (installs Go, builds tacctl, runs install -y)
#   rehearse.sh cross <local|new>  'tacctl upgrade --branch go-rehearsal' from
#                                  0.1.17, the branch pre-created in the clone
#                                  (local) or not (new); then version, a
#                                  second upgrade, and 'upgrade --branch master'
#
# The container's git fetches https://github.com/rett/tacctl.git from the
# scratch bare clone mounted at /srv/tacctl.git (url.insteadOf, set inside
# the container only).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BASE=localhost/tacctl-rehearsal:noble
INSTALLED=localhost/tacctl-rehearsal:installed-0.1.17
LOG="${HERE}/logs"
mkdir -p "$LOG"

start() { # start <name> <image>
    podman rm -f -t 0 "$1" > /dev/null 2>&1 || true
    podman run -d --name "$1" --hostname "$1" --systemd=always --cap-add SYS_ADMIN \
        -v "${HERE}/tacctl.git:/srv/tacctl.git:ro" "$2" /sbin/init > /dev/null
    sleep 5
    podman exec "$1" git config --global url./srv/tacctl.git.insteadOf https://github.com/rett/tacctl.git
}
# step <name> <container> <label> <command>: run, log, time.
step() {
    local name="$1" c="$2" label="$3" cmd="$4" t0 t1 rc
    echo "=== ${label}"
    echo "\$ ${cmd}" > "${LOG}/${name}.log"
    t0=$(date +%s)
    podman exec "$c" bash -c "$cmd" >> "${LOG}/${name}.log" 2>&1
    rc=$?
    t1=$(date +%s)
    echo "--- exit ${rc}, $((t1 - t0)) s (${LOG}/${name}.log)"
    return $rc
}
q() { podman exec "$1" bash -c "$2" 2>&1; }

case "${1:-}" in
install)
    start tacctl-rehearsal-install "$BASE"
    # 0.1.17 cannot install Go itself any more: it takes the checksum from
    # go.dev/dl/<tarball>.sha256, which now answers with a web page, so its
    # install stops at "Go tarball checksum mismatch!". Go is put in place
    # first, as on the dev server (verified against dl.google.com's checksum).
    # shellcheck disable=SC2016 # expanded inside the container
    step 0-go tacctl-rehearsal-install "Go 1.26.2 put in place (0.1.17's own download is broken)" \
        'cd /tmp && wget -q https://dl.google.com/go/go1.26.2.linux-amd64.tar.gz && [[ "$(sha256sum go1.26.2.linux-amd64.tar.gz | cut -d" " -f1)" == "$(wget -qO- https://dl.google.com/go/go1.26.2.linux-amd64.tar.gz.sha256)" ]] && tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz && rm go1.26.2.linux-amd64.tar.gz && /usr/local/go/bin/go version' || exit 1
    step 1-install tacctl-rehearsal-install "install 0.1.17 (README one-liner)" \
        "echo y | sudo bash -c 'git clone https://github.com/rett/tacctl.git /opt/tacctl && ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl && tacctl install'" || exit 1
    q tacctl-rehearsal-install 'tacctl version; git -C /opt/tacctl describe --tags; ls -l /usr/local/bin/tacctl; systemctl is-active tacquito; /usr/local/go/bin/go version'
    podman commit -q tacctl-rehearsal-install "$INSTALLED" > /dev/null && echo "committed ${INSTALLED}"
    podman rm -f -t 0 tacctl-rehearsal-install > /dev/null
    ;;
cross)
    mode="${2:?local|new}"
    c="tacctl-rehearsal-${mode}"
    start "$c" "$INSTALLED"
    q "$c" 'systemctl is-active tacquito; tacctl version'
    if [[ "$mode" == local ]]; then
        q "$c" 'git -C /opt/tacctl fetch -q origin && git -C /opt/tacctl branch go-rehearsal origin/go-rehearsal && git -C /opt/tacctl branch --list'
    else
        q "$c" 'git -C /opt/tacctl branch --list'
    fi
    before=$(q "$c" 'systemctl show tacquito -p ActiveEnterTimestamp --value')
    step "2-${mode}-cross" "$c" "upgrade --branch go-rehearsal (${mode} branch)" 'tacctl upgrade --branch go-rehearsal'
    echo "--- after the cross-over:"
    q "$c" 'ls -l /usr/local/bin/tacctl; tacctl version --long; systemctl is-active tacquito; ls /usr/local/bin/tacquito.bak 2>&1; du -sh /root/.cache/go-build'
    after=$(q "$c" 'systemctl show tacquito -p ActiveEnterTimestamp --value')
    echo "tacquito ActiveEnterTimestamp: before='${before}' after='${after}'"
    step "3-${mode}-again" "$c" "second upgrade (expect: no build, no restart)" 'tacctl upgrade'
    again=$(q "$c" 'systemctl show tacquito -p ActiveEnterTimestamp --value')
    echo "tacquito ActiveEnterTimestamp after the second upgrade: '${again}'"
    grep -nE 'Restarting|Building|restarting upgrade|Updated:|Installed:' "${LOG}/3-${mode}-again.log" || echo "(no build, restart or update lines)"
    q "$c" 'tacctl status > /dev/null && echo "status: ok"; tacctl config validate | tail -3'
    step "4-${mode}-back" "$c" "upgrade --branch master (back to 0.1.17)" 'tacctl upgrade --branch master'
    echo "--- after going back:"
    q "$c" 'ls -l /usr/local/bin/tacctl; tacctl version; git -C /opt/tacctl describe --tags; systemctl is-active tacquito; tacctl status > /dev/null && echo "status: ok (bash)"; tacctl config validate | tail -2'
    ;;
fresh)
    c=tacctl-rehearsal-fresh
    start "$c" "$BASE"
    step 5-fresh "$c" "0.2.0 fresh install through the shim (no Go on the host)" \
        "git clone -q --branch go-rehearsal https://github.com/rett/tacctl.git /opt/tacctl && /opt/tacctl/bin/tacctl.sh install -y"
    q "$c" 'ls -l /usr/local/bin/tacctl; tacctl version --long; /usr/local/go/bin/go version; systemctl is-active tacquito; tacctl status > /dev/null && echo "status: ok"; tacctl config validate | tail -2; ls /etc/tacctl/templates/ /etc/bash_completion.d/tacctl /usr/share/man/man1/tacctl.1.gz'
    step 6-fresh-again "$c" "upgrade right after the fresh install" 'tacctl upgrade'
    grep -nE 'Restarting|Building|Updated:|Installed:' "${LOG}/6-fresh-again.log" || echo "(no build, restart or update lines)"
    step 7-fresh-uninstall "$c" "uninstall -y" 'tacctl uninstall -y'
    q "$c" 'ls -d /opt/tacctl /etc/tacctl /etc/tacquito /usr/local/bin/tacctl /etc/bash_completion.d/tacctl /usr/share/man/man1/tacctl.1.gz /usr/local/go /opt/tacquito-src 2>&1; id tacquito 2>&1; systemctl list-unit-files "tacquito*" --no-legend'
    ;;
*)
    echo "usage: rehearse.sh install | fresh | cross <local|new>" >&2
    exit 2
    ;;
esac
