# --- tacctl Linux client: install / account sync -------------------------------
# Body of the script emitted by 'tacctl config linux script'. tacctl prepends
# a header that sets TAC_SERVER, TAC_PORT, TAC_SECRET, TAC_SCOPE,
# TARBALL_SHA256 and TAC_USERS, and appends the pam_tacplus source tarball
# (base64) after the __TARBALL__ marker. Run as root on the target host:
#
#   bash tacctl-linux-<scope>.sh                  full install (or re-install)
#   bash tacctl-linux-<scope>.sh --accounts-only  sync accounts and groups only
#
# TACCTL_FORCE=1 skips the local-administrator (lockout) check.
# shellcheck shell=bash disable=SC2154,SC2317

STATE_DIR="${TACCTL_CLIENT_STATE:-/var/lib/tacctl-client}"
PAM_DIR="${TACCTL_CLIENT_PAM_DIR:-/etc/pam.d}"
SUDOERS_HOST_FILE="${TACCTL_CLIENT_SUDOERS:-/etc/sudoers.d/tacctl-host}"
PAM_SERVICES="sshd sudo login"
G_USERS="tac-users"

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

ACCOUNTS_ONLY=0
case "${1:-}" in
    "") ;;
    --accounts-only) ACCOUNTS_ONLY=1 ;;
    *) die "Unknown argument '$1'. Usage: $0 [--accounts-only]" ;;
esac

# TACCTL_CLIENT_TEST=1 is for the bats suite only: it skips the root check
# and the module build so the account and PAM logic can run unprivileged
# against scratch directories.
CLIENT_TEST="${TACCTL_CLIENT_TEST:-0}"
[[ $EUID -eq 0 || "$CLIENT_TEST" == "1" ]] || die "Run as root (sudo bash $0)."
command -v apt-get >/dev/null || die "Only Debian/Ubuntu hosts are supported so far."

# Names of the TACACS+ users this script manages, one per line.
tac_user_names() {
    local name _rest
    while IFS=: read -r name _rest; do
        if [[ -n "$name" ]]; then echo "$name"; fi
    done <<< "$TAC_USERS"
    return 0
}

# A local administrator who does not depend on TACACS+: root or a member of
# sudo/wheel/admin with a usable local password, and not a managed user.
local_admins() {
    local managed candidates user pw
    managed=$(tac_user_names)
    candidates="root $(getent group sudo wheel admin 2>/dev/null | cut -d: -f4 | tr ',\n' '  ')"
    for user in $candidates; do
        grep -qxF "$user" <<< "$managed" && continue
        pw=$(getent shadow "$user" 2>/dev/null | cut -d: -f2)
        if [[ -n "$pw" && "$pw" != '!'* && "$pw" != '*'* ]]; then echo "$user"; fi
    done
    return 0
}

if [[ "${TACCTL_FORCE:-0}" != "1" && -z "$(local_admins)" ]]; then
    die "No local administrator with a usable password exists outside the TACACS+ user list.
        Every sudo-capable account would depend on the TACACS+ server. Give one local
        admin account a password first, or re-run with TACCTL_FORCE=1."
fi

mkdir -p "$STATE_DIR/backup"
chmod 700 "$STATE_DIR"
touch "$STATE_DIR/created" "$STATE_DIR/adopted" "$STATE_DIR/expired"

# --- Accounts and groups -------------------------------------------------------
sync_accounts() {
    local g name tier uid managed member
    for g in "$G_USERS" tac-readonly tac-operator tac-superuser; do
        getent group "$g" >/dev/null || groupadd "$g"
    done

    while IFS=: read -r name tier uid; do
        [[ -n "$name" ]] || continue
        if getent passwd "$name" >/dev/null; then
            if ! grep -qxF "$name" "$STATE_DIR/created" "$STATE_DIR/adopted"; then
                echo "$name" >> "$STATE_DIR/adopted"
                info "Adopted existing account '${name}' (local password left as it is)."
            fi
        else
            # New accounts get a locked password: TACACS+ is their only password.
            if getent passwd "$uid" >/dev/null; then
                warn "UID ${uid} is taken on this host; '${name}' gets the next free UID."
                useradd -m -s /bin/bash -c "TACACS+ user (tacctl)" "$name"
            else
                useradd -m -u "$uid" -s /bin/bash -c "TACACS+ user (tacctl)" "$name"
            fi
            echo "$name" >> "$STATE_DIR/created"
            info "Created account '${name}' (${tier})."
        fi
        for g in tac-readonly tac-operator tac-superuser; do
            if [[ "$g" != "tac-${tier}" && " $(id -nG "$name") " == *" $g "* ]]; then
                gpasswd -d "$name" "$g" >/dev/null
            fi
        done
        usermod -aG "${G_USERS},tac-${tier}" "$name"
        if grep -qxF "$name" "$STATE_DIR/expired"; then
            usermod -e '' "$name"
            sed -i "/^${name}\$/d" "$STATE_DIR/expired"
            info "Re-activated account '${name}'."
        fi
    done <<< "$TAC_USERS"

    # Users no longer in the scope: drop the tier groups. Accounts this
    # script created are also expired, which blocks SSH-key logins too;
    # adopted accounts go back to being plain local accounts.
    managed=$(tac_user_names)
    for member in $(getent group "$G_USERS" | cut -d: -f4 | tr ',' ' '); do
        grep -qxF "$member" <<< "$managed" && continue
        for g in "$G_USERS" tac-readonly tac-operator tac-superuser; do
            gpasswd -d "$member" "$g" >/dev/null 2>&1 || true
        done
        if grep -qxF "$member" "$STATE_DIR/created"; then
            usermod -e 1 "$member"
            echo "$member" >> "$STATE_DIR/expired"
            info "'${member}' is no longer a TACACS+ user here: account expired, files kept."
        else
            info "'${member}' is no longer a TACACS+ user here: removed from the tac-* groups."
        fi
    done
}

sync_accounts
if [[ "$ACCOUNTS_ONLY" == "1" ]]; then
    info "Accounts synced for scope '${TAC_SCOPE}'."
    exit 0
fi

# --- Build pam_tacplus from the embedded source tarball ------------------------
for svc in sshd sudo; do
    [[ -f "$PAM_DIR/$svc" ]] || die "$PAM_DIR/$svc not found."
    if ! grep -qE '^@include[[:space:]]+(common-auth|tacctl-auth)[[:space:]]*$' "$PAM_DIR/$svc"; then
        die "$PAM_DIR/$svc has no '@include common-auth' line; refusing to edit an unfamiliar PAM layout."
    fi
done

build_dir=$(mktemp -d)
pam_edit_started=0
pam_committed=0
restore_pam() {
    local svc
    for svc in $PAM_SERVICES; do
        if [[ -f "$STATE_DIR/backup/$svc" ]]; then
            cp -p "$STATE_DIR/backup/$svc" "$PAM_DIR/$svc"
        fi
    done
    rm -f "$PAM_DIR/tacctl-auth" "$PAM_DIR/tacctl-account" "$PAM_DIR/tacctl-session"
    warn "Install failed: PAM service files restored from backup, TACACS+ not enabled."
}
# Any exit before the final commit puts the PAM service files back.
cleanup() {
    if [[ "$pam_edit_started" == "1" && "$pam_committed" != "1" ]]; then
        restore_pam
    fi
    rm -rf "$build_dir"
}
trap cleanup EXIT
if [[ "$CLIENT_TEST" != "1" ]]; then
need_pkgs=""
command -v gcc  >/dev/null || need_pkgs+=" gcc"
command -v make >/dev/null || need_pkgs+=" make"
[[ -f /usr/include/security/pam_modules.h ]] || need_pkgs+=" libpam0g-dev"
if [[ -n "$need_pkgs" ]]; then
    info "Installing build packages:${need_pkgs}"
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y $need_pkgs >/dev/null
fi

sed -n '/^__TARBALL__$/,$p' "$0" | tail -n +2 | base64 -d > "$build_dir/src.tar.gz"
echo "${TARBALL_SHA256}  $build_dir/src.tar.gz" | sha256sum -c --quiet \
    || die "Embedded pam_tacplus tarball failed its checksum."
tar -C "$build_dir" -xzf "$build_dir/src.tar.gz"

multiarch=$(gcc -print-multiarch 2>/dev/null || true)
lib_dir="/usr/lib${multiarch:+/$multiarch}"
sec_dir=""
for d in "$lib_dir/security" /usr/lib64/security /usr/lib/security /lib/security; do
    if [[ -f "$d/pam_unix.so" ]]; then sec_dir="$d"; break; fi
done
[[ -n "$sec_dir" ]] || die "Could not find the PAM module directory."

if [[ -e "$lib_dir/libtac.so.5" && ! -f "$STATE_DIR/installed" ]]; then
    die "$lib_dir/libtac.so.5 already exists and was not installed by tacctl. Remove the other libtac first."
fi

info "Building pam_tacplus (this takes a minute)..."
(
    cd "$build_dir"/pam_tacplus-*/
    ./configure --prefix=/usr --libdir="$lib_dir" --enable-pamdir="$sec_dir" >"$build_dir/build.log" 2>&1
    make >>"$build_dir/build.log" 2>&1
    make install DESTDIR="$build_dir/stage" >>"$build_dir/build.log" 2>&1
) || { tail -20 "$build_dir/build.log" >&2; die "pam_tacplus build failed."; }

install -m 0644 "$build_dir/stage$lib_dir/libtac.so.5.0.0" "$lib_dir/libtac.so.5.0.0"
ln -sf libtac.so.5.0.0 "$lib_dir/libtac.so.5"
install -m 0644 "$build_dir/stage$sec_dir/pam_tacplus.so" "$sec_dir/pam_tacplus.so"
ldconfig
{
    echo "$lib_dir/libtac.so.5.0.0"
    echo "$lib_dir/libtac.so.5"
    echo "$sec_dir/pam_tacplus.so"
} > "$STATE_DIR/files"
fi

# --- PAM -----------------------------------------------------------------------
# Only members of tac-users are sent to TACACS+; everyone else skips straight
# to the distribution's own stack. A reject from the server is final. An
# unreachable server falls through to the local password, which only
# adopted accounts have.
#
# pam_tacplus takes the shared secret as a module argument, so these files
# are root-only. sshd, sudo and login all read PAM config as root.
if [[ "$TAC_SERVER" == *:* ]]; then
    tac_args="server=[${TAC_SERVER}]:${TAC_PORT}"
else
    tac_args="server=${TAC_SERVER}:${TAC_PORT}"
fi
tac_args+=" secret=${TAC_SECRET} timeout=3 login=pap service=shell protocol=ssh"
gate="pam_succeed_if.so quiet user ingroup ${G_USERS}"
pam_edit_started=1

write_pam() {
    local file="$PAM_DIR/$1"
    install -m 0600 -o root -g root /dev/null "$file"
    cat > "$file"
}
write_pam tacctl-auth <<EOF
# Managed by tacctl (scope ${TAC_SCOPE}). Do not edit; re-run the install script.
auth    [success=ok default=1]                               ${gate}
auth    [success=done authinfo_unavail=ignore default=die]   pam_tacplus.so ${tac_args}
@include common-auth
EOF
# Authorization is only possible in the process that did the TACACS+
# authentication; for SSH-key logins the module reports auth_err, which is
# ignored here. Removed or disabled users are handled by account sync.
write_pam tacctl-account <<EOF
# Managed by tacctl (scope ${TAC_SCOPE}). Do not edit; re-run the install script.
account [success=ok default=1]                               ${gate}
account [success=ok perm_denied=die default=ignore]          pam_tacplus.so ${tac_args}
@include common-account
EOF
write_pam tacctl-session <<EOF
# Managed by tacctl (scope ${TAC_SCOPE}). Do not edit; re-run the install script.
session [success=ok default=1]                               ${gate}
session optional                                             pam_tacplus.so ${tac_args}
EOF

for svc in $PAM_SERVICES; do
    f="$PAM_DIR/$svc"
    [[ -f "$f" ]] || continue
    # Keep the first backup: it is the pre-tacctl original.
    [[ -f "$STATE_DIR/backup/$svc" ]] || cp -p "$f" "$STATE_DIR/backup/$svc"
    sed -i -E \
        -e 's/^@include[[:space:]]+common-auth[[:space:]]*$/@include tacctl-auth/' \
        -e 's/^@include[[:space:]]+common-account[[:space:]]*$/@include tacctl-account/' "$f"
    if [[ "$svc" != "sudo" ]] && ! grep -q '^@include tacctl-session$' "$f"; then
        sed -i -E '/^@include[[:space:]]+common-session[[:space:]]*$/a @include tacctl-session' "$f"
    fi
done
grep -q '^@include tacctl-auth$' "$PAM_DIR/sshd" || die "Failed to edit $PAM_DIR/sshd."
grep -q '^@include tacctl-auth$' "$PAM_DIR/sudo" || die "Failed to edit $PAM_DIR/sudo."

# --- sudo for superusers -------------------------------------------------------
sudoers_tmp=$(mktemp)
cat > "$sudoers_tmp" <<EOF
# Managed by tacctl. TACACS+ superusers get full sudo (password required).
%tac-superuser ALL=(ALL:ALL) ALL
EOF
visudo -cf "$sudoers_tmp" >/dev/null || die "visudo rejected the sudoers drop-in."
install -m 0440 -o root -g root "$sudoers_tmp" "$SUDOERS_HOST_FILE"
rm -f "$sudoers_tmp"

pam_committed=1
{
    echo "scope=${TAC_SCOPE}"
    echo "server=${TAC_SERVER}:${TAC_PORT}"
    echo "installed=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$STATE_DIR/installed"

# --- Post-install checks -------------------------------------------------------
if ! timeout 4 bash -c "exec 3<>/dev/tcp/${TAC_SERVER}/${TAC_PORT}" 2>/dev/null; then
    warn "Cannot reach ${TAC_SERVER} port ${TAC_PORT} from this host. TACACS+ logins will fail until it is reachable."
fi
if command -v sshd >/dev/null; then
    sshd_conf=$(sshd -T 2>/dev/null || true)
    grep -qi '^usepam yes' <<< "$sshd_conf" \
        || warn "sshd has 'UsePAM no': SSH logins will not use TACACS+."
    grep -qi '^passwordauthentication yes' <<< "$sshd_conf" \
        || warn "sshd has 'PasswordAuthentication no': TACACS+ users cannot log in over SSH with a password."
fi

info "TACACS+ authentication installed for scope '${TAC_SCOPE}' (server ${TAC_SERVER}:${TAC_PORT})."
info "Local administrators unaffected by TACACS+: $(local_admins | paste -sd' ')"
info "Keep this session open and test from a second one: ssh <tacacs-user>@$(hostname)"
exit 0
