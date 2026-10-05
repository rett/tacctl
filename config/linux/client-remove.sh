#!/usr/bin/env bash
# --- tacctl Linux client: remove -----------------------------------------------
# Emitted by 'tacctl config linux remove-script'. Takes TACACS+ or RADIUS
# authentication back out of a host, whichever method it was enrolled with
# (everything of both is removed, so a host caught halfway through a switch
# comes out clean too): the PAM edits, the pam_tacplus module, the
# pam_radius_auth server file with the shared secret, the SELinux modules
# and the sudoers drop-in. Local accounts, home directories and the tac-*
# groups are left in place, and so are packages the install added
# (pam_radius_auth, EPEL, build tools); tacctl's accounts whose login shell
# is the tacctl console get /bin/bash back. Contains no secrets. Run as root
# on the target host.
#
# TACCTL_FORCE=1 skips the local-administrator (lockout) check.
set -euo pipefail
umask 077

STATE_DIR="${TACCTL_CLIENT_STATE:-/var/lib/tacctl-client}"
PAM_DIR="${TACCTL_CLIENT_PAM_DIR:-/etc/pam.d}"
XDG_DIR="${TACCTL_CLIENT_XDG:-/etc/xdg}"
SUDOERS_HOST_FILE="${TACCTL_CLIENT_SUDOERS:-/etc/sudoers.d/tacctl-host}"
# sudo-i is the service 'sudo -i' uses; where it exists it has its own copy
# of the includes (Debian) or simply includes sudo (RHEL family). sddm and
# gdm-password are the graphical logins; GNOME's lock screen also unlocks
# through gdm-password. Files a host does not have are skipped.
PAM_SERVICES="sshd sudo sudo-i login sddm gdm-password"
G_USERS="tac-users"

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# TACCTL_CLIENT_TEST=1 is for the bats suite only (skips the root check).
[[ $EUID -eq 0 || "${TACCTL_CLIENT_TEST:-0}" == "1" ]] || die "Run as root (sudo bash $0)."

# Where the install script keeps pam_radius_auth's server file.
RADIUS_CONF="${TACCTL_CLIENT_RADIUS_CONF:-/etc/tacctl-pam_radius.conf}"
if [[ "${TACCTL_CLIENT_TEST:-0}" == "1" && -z "${TACCTL_CLIENT_RADIUS_CONF:-}" ]]; then
    RADIUS_CONF="$STATE_DIR/pam_radius.conf"
fi

# What the messages call the method this host has. A host enrolled before
# there were two has no method file: it has tacplus.
PROTO="TACACS+"
if [[ "$(cat "$STATE_DIR/method" 2>/dev/null || true)" == "radius" ]]; then PROTO="RADIUS"; fi

usable_password() {
    local pw
    pw=$(getent shadow "$1" 2>/dev/null | cut -d: -f2)
    [[ -n "$pw" && "$pw" != '!'* && "$pw" != '*'* ]]
}

# Once the server's passwords are gone, someone must still be able to become root.
admins=""
for user in root $(getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr ',\n' '  '); do
    if usable_password "$user"; then admins+=" $user"; fi
done
if [[ "${TACCTL_FORCE:-0}" != "1" && -z "$admins" ]]; then
    die "No administrator has a usable local password. Removing ${PROTO} would lock
        everyone out of sudo. Set a local password first, or re-run with TACCTL_FORCE=1."
fi

# Accounts tacctl created whose login shell is the tacctl console (the
# tacctl server's own) get /bin/bash back before anything else: the console
# needs this server's tacctl, which may be the next thing to go. Any other
# account with that shell is named and left as it is.
while IFS=: read -r name _ _ _ _ _ shell; do
    [[ "${shell##*/}" == "tacctl-console" ]] || continue
    if grep -qxF "$name" "$STATE_DIR/created" 2>/dev/null; then
        usermod -s /bin/bash "$name"
        info "'${name}': login shell is /bin/bash again (it was the tacctl console)."
    else
        warn "'${name}' has the tacctl console (${shell}) as its login shell, but tacctl did not create it; left as it is."
    fi
done < <(getent passwd)

# Undo the edits rather than copying the backups back, so package updates
# made to these files since the install are kept.
for svc in $PAM_SERVICES; do
    f="$PAM_DIR/$svc"
    [[ -f "$f" ]] || continue
    sed -i -E \
        -e 's/^@include tacctl-auth$/@include common-auth/' \
        -e 's/^@include tacctl-account$/@include common-account/' \
        -e '/^@include tacctl-session$/d' \
        -e '/^(auth|account|session)[[:space:]]+include[[:space:]]+tacctl-(auth|account|session)$/d' "$f"
    if grep -q 'tacctl-' "$f"; then
        die "$f still references tacctl PAM files; fix it by hand before continuing (original: $STATE_DIR/backup/$svc)."
    fi
done
rm -f "$PAM_DIR/tacctl-auth" "$PAM_DIR/tacctl-account" "$PAM_DIR/tacctl-session"
# The secret was on the pam_tacplus lines, or in pam_radius_auth's server file.
rm -f "$RADIUS_CONF"
info "PAM service files restored; shared secret removed."

rm -f "$SUDOERS_HOST_FILE"

# KDE Plasma: the accounts may lock the screen again.
rm -f "$XDG_DIR/plasma-workspace/env/tacctl-nolock.sh" "$XDG_DIR/tacctl/kscreenlockerrc" "$XDG_DIR/tacctl/kdeglobals"
rmdir "$XDG_DIR/tacctl" 2>/dev/null || true

if [[ -f "$STATE_DIR/files" ]]; then
    while IFS= read -r path; do
        if [[ "$path" == /usr/lib/* || "$path" == /usr/lib64/* || "$path" == /lib/* ]]; then rm -f "$path"; fi
    done < "$STATE_DIR/files"
    ldconfig
    rm -f "$STATE_DIR/files"
fi
rm -f "$STATE_DIR/installed" "$STATE_DIR/module" "$STATE_DIR/method"

for mod in tacctl_pam tacctl_pam_radius; do
    if [[ -f "$STATE_DIR/${mod}.cil" ]]; then
        if command -v semodule >/dev/null; then semodule -r "$mod" 2>/dev/null || true; fi
        rm -f "$STATE_DIR/${mod}.cil"
    fi
done

# Report accounts that now have no way to log in. Nothing is changed.
orphans=""
for member in $(getent group "$G_USERS" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
    if usable_password "$member"; then continue; fi
    home=$(getent passwd "$member" | cut -d: -f6)
    if [[ -s "$home/.ssh/authorized_keys" ]]; then continue; fi
    orphans+=" $member"
done

info "${PROTO} authentication removed. Accounts, home directories and tac-* groups were left in place."
if [[ -n "$orphans" ]]; then
    warn "These accounts have no local password and no SSH key, so they cannot log in:${orphans}"
fi
if [[ -s "$STATE_DIR/packages" ]]; then
    info "Packages the install added were left installed: $(paste -sd' ' "$STATE_DIR/packages")"
fi
info "Originals of the edited PAM files remain in $STATE_DIR/backup."
