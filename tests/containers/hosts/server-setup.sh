#!/bin/bash
# Server side of the Linux-host container check (see run.sh), inside the
# systemd server container with this checkout mounted read-only at
# /opt/tacctl:
#
#   server-setup.sh <tacplus|radius|both>
#
# Writes a store with three users (real bcrypt hashes; passwords below),
# brings up tacquito under its unit when the image has the binary, and runs
# 'tacctl backend enable radius' for real. Prints the versions of what serves.
set -u
WANT="${1:?usage: server-setup.sh <tacplus|radius|both>}"
git config --global --add safe.directory /opt/tacctl 2> /dev/null
mkdir -p /etc/tacctl
chmod 700 /etc/tacctl
ln -sf /opt/tacctl/bin/tacctl.sh /usr/local/bin/tacctl

python3 - > /etc/tacctl/store.yaml <<'PY'
import binascii, bcrypt
def h(pw):
    return binascii.hexlify(bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=10))).decode()
print(f'''version: 1
groups:
  operator: {{priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}}
  readonly: {{priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}}
  superuser: {{priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}}
users:
  alice: {{group: superuser, scopes: [lab], hash: {h("Alice-Net-Pw-1")}, disabled: false}}
  bob: {{group: operator, scopes: [lab], hash: {h("Bob-Net-Pw-1")}, disabled: false}}
  carl: {{group: readonly, scopes: [lab], hash: {h("Carl-Net-Pw-1")}, disabled: false}}
scopes:
  lab:
    prefixes: [192.0.2.0/24]
    secret: lab-secret-0123456789abcdef
''')
PY
chmod 600 /etc/tacctl/store.yaml

if [[ "$WANT" != "radius" ]]; then
    if [[ ! -x /usr/local/bin/tacquito || ! -f /var/lib/tacctl/linux/pam_tacplus-1.7.0.tar.gz ]]; then
        echo "FAIL  this server image has no tacquito binary or no pam_tacplus tarball (see run.sh): tacplus cannot be checked"
        exit 1
    fi
    # The TACACS+ backend's own install phases, minus the Go build.
    bash -c 'set -euo pipefail; source /opt/tacctl/bin/tacctl.sh
        backend_tacacs_install account /opt/tacctl
        "$0" config render > /dev/null 2>&1 || true
        backend_tacacs_install start /opt/tacctl' /usr/local/bin/tacctl 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tail -3
    systemctl is-active --quiet tacquito || { echo "FAIL  tacquito did not start"; journalctl -u tacquito -n 20 --no-pager; exit 1; }
    echo "tacquito: $(sha256sum /usr/local/bin/tacquito | cut -c1-12) (the binary of the machine that built the image), listening on $(ss -tlnH | awk '$4 ~ /:49$/ {print $4}' | head -1)"
else
    mkdir -p /etc/tacquito /var/log/tacquito
    tacctl config render > /dev/null 2>&1 || true
fi

if [[ "$WANT" != "tacplus" ]]; then
    tacctl backend enable radius -y 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'ERROR|enabled and running' | tail -3
    unit=freeradius; systemctl cat radiusd > /dev/null 2>&1 && unit=radiusd
    systemctl is-active --quiet "$unit" || { echo "FAIL  ${unit} did not start"; exit 1; }
    echo "FreeRADIUS: $("$(command -v freeradius || command -v radiusd)" -v | head -1 | sed 's/, for host.*//')"
fi
exit 0
