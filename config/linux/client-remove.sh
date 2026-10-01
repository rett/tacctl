#!/usr/bin/env bash
# --- tacctl Linux client: remove -----------------------------------------------
# Emitted by 'tacctl config linux remove-script'. Takes TACACS+ authentication
# back out of a host: PAM edits, the pam_tacplus module, and the sudoers
# drop-in. Local accounts, home directories and the tac-* groups are left in
# place. Contains no secrets. Run as root on the target host.
#
# TACCTL_FORCE=1 skips the local-administrator (lockout) check.
set -euo pipefail
umask 077

STATE_DIR="${TACCTL_CLIENT_STATE:-/var/lib/tacctl-client}"
PAM_DIR="${TACCTL_CLIENT_PAM_DIR:-/etc/pam.d}"
SUDOERS_HOST_FILE="${TACCTL_CLIENT_SUDOERS:-/etc/sudoers.d/tacctl-host}"
PAM_SERVICES="sshd sudo login"
G_USERS="tac-users"

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# TACCTL_CLIENT_TEST=1 is for the bats suite only (skips the root check).
[[ $EUID -eq 0 || "${TACCTL_CLIENT_TEST:-0}" == "1" ]] || die "Run as root (sudo bash $0)."

usable_password() {
    local pw
    pw=$(getent shadow "$1" 2>/dev/null | cut -d: -f2)
    [[ -n "$pw" && "$pw" != '!'* && "$pw" != '*'* ]]
}

# Once TACACS+ is gone, someone must still be able to become root.
admins=""
for user in root $(getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr ',\n' '  '); do
    if usable_password "$user"; then admins+=" $user"; fi
done
if [[ "${TACCTL_FORCE:-0}" != "1" && -z "$admins" ]]; then
    die "No administrator has a usable local password. Removing TACACS+ would lock
        everyone out of sudo. Set a local password first, or re-run with TACCTL_FORCE=1."
fi

# Undo the edits rather than copying the backups back, so package updates
# made to these files since the install are kept.
for svc in $PAM_SERVICES; do
    f="$PAM_DIR/$svc"
    [[ -f "$f" ]] || continue
    sed -i -E \
        -e 's/^@include tacctl-auth$/@include common-auth/' \
        -e 's/^@include tacctl-account$/@include common-account/' \
        -e '/^@include tacctl-session$/d' "$f"
    if grep -q 'tacctl-' "$f"; then
        die "$f still references tacctl PAM files; fix it by hand before continuing (original: $STATE_DIR/backup/$svc)."
    fi
done
rm -f "$PAM_DIR/tacctl-auth" "$PAM_DIR/tacctl-account" "$PAM_DIR/tacctl-session"
info "PAM service files restored; shared secret removed."

rm -f "$SUDOERS_HOST_FILE"

if [[ -f "$STATE_DIR/files" ]]; then
    while IFS= read -r path; do
        if [[ "$path" == /usr/lib/* || "$path" == /lib/* ]]; then rm -f "$path"; fi
    done < "$STATE_DIR/files"
    ldconfig
    rm -f "$STATE_DIR/files"
fi
rm -f "$STATE_DIR/installed"

# Report accounts that now have no way to log in. Nothing is changed.
orphans=""
for member in $(getent group "$G_USERS" 2>/dev/null | cut -d: -f4 | tr ',' ' '); do
    if usable_password "$member"; then continue; fi
    home=$(getent passwd "$member" | cut -d: -f6)
    if [[ -s "$home/.ssh/authorized_keys" ]]; then continue; fi
    orphans+=" $member"
done

info "TACACS+ authentication removed. Accounts, home directories and tac-* groups were left in place."
if [[ -n "$orphans" ]]; then
    warn "These accounts have no local password and no SSH key, so they cannot log in:${orphans}"
fi
info "Originals of the edited PAM files remain in $STATE_DIR/backup."
