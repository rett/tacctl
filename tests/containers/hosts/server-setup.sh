#!/bin/bash
# Server side of the Linux-host container check (see run.sh), inside the
# systemd server container with this checkout mounted read-only at
# /opt/tacctl:
#
#   server-setup.sh <tacplus|radius|both>
#
# Writes a store with five users (real bcrypt hashes; passwords below),
# brings up tacquito under its unit when the image has the binary, and runs
# 'tacctl backend enable radius' for real. Prints the versions of what serves.
set -u
WANT="${1:?usage: server-setup.sh <tacplus|radius|both>}"
git config --global --add safe.directory /opt/tacctl 2> /dev/null
mkdir -p /etc/tacctl
chmod 700 /etc/tacctl
# The bootstrap builds /usr/local/bin/tacctl from the checkout when the one
# in the image is not from this commit.
/opt/tacctl/bin/tacctl.sh version > /dev/null 2>&1 || { echo "FAIL  tacctl could not be built from /opt/tacctl"; exit 1; }
# A checkout with changes not committed yet carries its HEAD's commit, which
# the bootstrap takes as current: build the working tree as it is.
if [[ -n "$(git -C /opt/tacctl status --porcelain 2> /dev/null)" ]]; then
    /opt/tacctl/bin/tacctl.sh --build /usr/local/bin/tacctl || { echo "FAIL  tacctl could not be built from the working tree in /opt/tacctl"; exit 1; }
fi

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
  dave: {{group: readonly, scopes: [lab], hash: {h("Dave-Net-Pw-1")}, disabled: false}}
  erin: {{group: readonly, scopes: [lab], hash: {h("Erin-Net-Pw-1")}, disabled: false}}
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
    { tacctl _phase tacacs install account /opt/tacctl \
        && { tacctl config render > /dev/null 2>&1 || true; tacctl _phase tacacs install start /opt/tacctl; }; } 2>&1 \
        | sed 's/\x1b\[[0-9;]*m//g' | tail -3
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
