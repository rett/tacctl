#!/bin/bash
# Client side of the Linux-host container check (see run.sh): turns a stock
# distribution image into something that looks like a small server, run once
# when the client image is built. Nothing of tacctl, no PAM module, no EPEL:
# enrollment has to bring those.
#
# - sshd, an ssh client and sudo;
# - 'ladm', a local administrator (sudo/wheel) with a local password, and
#   'carl', an ordinary pre-existing account with a local password that the
#   check has tacctl adopt;
# - /etc/pam.d/gdm-password, a stand-in with the lines the distribution's GDM
#   package has around its includes (no GDM is installed), so the graphical
#   login's service file is edited and can be driven by a PAM client;
# - python3 for that PAM client (pamprobe.py), where the image has none;
# - what a rootless container needs and a real host does not: pam_loginuid
#   commented out (no audit loginuid there), pam_unix's account step
#   replaced by pam_permit and, on the RHEL family, /etc/shadow readable by
#   its owner (pam_unix's helper unix_chkpwd cannot use root's capabilities
#   there); and the container must run with --cap-add AUDIT_WRITE.
# shellcheck disable=SC2016  # the askpass script expands its own variable
set -euo pipefail
if command -v apt-get > /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq openssh-server openssh-client sudo python3 > /dev/null
    admin_group=sudo
    sed -i -E 's/^(account.*)pam_unix\.so.*/\1pam_permit.so/' /etc/pam.d/common-account
    printf '%s\n' '#%PAM-1.0' 'auth    requisite       pam_nologin.so' \
        'auth    required        pam_succeed_if.so user != root quiet_success' '@include common-auth' \
        '@include common-account' 'session required        pam_limits.so' '@include common-session' \
        '@include common-password' > /etc/pam.d/gdm-password
else
    dnf install -y -q openssh-server openssh-clients sudo passwd util-linux > /dev/null
    admin_group=wheel
    sed -i -E 's/^(account[[:space:]]+required[[:space:]]+)pam_unix\.so.*/\1pam_permit.so/' /etc/pam.d/password-auth /etc/pam.d/system-auth
    rm -f /run/nologin
    # pam_unix checks local passwords through its helper unix_chkpwd, which
    # drops its capabilities and then cannot read a mode-0000 /etc/shadow in
    # a rootless container.
    chmod 0400 /etc/shadow
    printf '%s\n' '#%PAM-1.0' 'auth        substack      password-auth' 'account     required      pam_nologin.so' \
        'account     include       password-auth' 'password    substack      password-auth' \
        'session     include       password-auth' > /etc/pam.d/gdm-password
fi
sed -i -E 's/^(session.*pam_loginuid\.so)/#\1/' /etc/pam.d/*
ssh-keygen -A > /dev/null
mkdir -p /run/sshd /root/.ssh
chmod 700 /root/.ssh
cat >> /etc/ssh/sshd_config <<'CONF'
PasswordAuthentication yes
UsePAM yes
PermitRootLogin prohibit-password
CONF
# A later 'PasswordAuthentication no' in a drop-in read first would win.
rm -f /etc/ssh/sshd_config.d/*.conf
useradd -m -s /bin/bash -G "$admin_group" ladm
useradd -m -s /bin/bash carl
printf '%s\n' 'ladm:Local-Admin-Pw-1' 'carl:Carl-Local-Pw-1' | chpasswd
# The password for ssh comes from the environment (THC_PW).
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$THC_PW"' > /usr/local/bin/thc-askpass
chmod 755 /usr/local/bin/thc-askpass
