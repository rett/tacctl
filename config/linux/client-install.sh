# --- tacctl Linux client: install / account sync -------------------------------
# Body of the script emitted by 'tacctl config linux script'. tacctl prepends
# a header that sets TAC_SERVER, TAC_PORT, TAC_SECRET, TAC_SCOPE,
# TARBALL_SHA256 and TAC_USERS, and appends the pam_tacplus source tarball
# (base64) after the __TARBALL__ marker. Run as root on the target host:
#
#   bash tacctl-linux-<scope>.sh                  full install (or re-install)
#   bash tacctl-linux-<scope>.sh --accounts-only  sync accounts and groups only
#   --allow-uid-mismatch (either form)            accept UID/GID conflicts on this host
#   --adopt <name>[,<name>...] (either form)      take over pre-existing accounts
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
ALLOW_UID_MISMATCH=0
ADOPT=""    # comma-separated names of pre-existing accounts to take over
while [[ $# -gt 0 ]]; do
    case "$1" in
        --accounts-only)      ACCOUNTS_ONLY=1; shift ;;
        --allow-uid-mismatch) ALLOW_UID_MISMATCH=1; shift ;;
        --adopt)
            [[ -n "${2:-}" ]] || die "--adopt needs a comma-separated list of account names."
            ADOPT+="${ADOPT:+,}$2"; shift 2
            ;;
        *) die "Unknown argument '$1'. Usage: $0 [--accounts-only] [--allow-uid-mismatch] [--adopt <name>[,<name>...]]" ;;
    esac
done

# TACCTL_CLIENT_TEST=1 is for the bats suite only: it skips the root check
# and fakes the module build so the account and PAM logic can run unprivileged
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

# id_is_free <name> <id>: the number is unused as a UID, and as a GID is
# either unused or already the group named <name>.
id_is_free() {
    local name="$1" id="$2" gname ggid
    if getent passwd "$id" >/dev/null; then return 1; fi
    gname=$(getent group "$id" | cut -d: -f1 || true)
    if [[ -n "$gname" && "$gname" != "$name" ]]; then return 1; fi
    ggid=$(getent group "$name" | cut -d: -f3 || true)
    if [[ -n "$ggid" && "$ggid" != "$id" ]]; then return 1; fi
    return 0
}

# --- UID/GID consistency -------------------------------------------------------
# tacctl gives each user one number, used as both UID and primary GID on
# every host. Nothing is created or changed until every user in the list
# can have that number here, unless --allow-uid-mismatch was given.
check_ids() {
    local name _tier uid cur owner conflicts="" mismatches=""
    while IFS=: read -r name _tier uid; do
        [[ -n "$name" ]] || continue
        if getent passwd "$name" >/dev/null; then
            cur=$(getent passwd "$name" | cut -d: -f3)
            if [[ "$cur" != "$uid" ]]; then
                mismatches+="    ${name}: UID ${cur} on this host, ${uid} assigned by tacctl"$'\n'
            fi
            continue
        fi
        owner=$(getent passwd "$uid" | cut -d: -f1 || true)
        if [[ -n "$owner" ]]; then
            conflicts+="    ${name}: UID ${uid} already belongs to user '${owner}'"$'\n'
        fi
        owner=$(getent group "$uid" | cut -d: -f1 || true)
        if [[ -n "$owner" && "$owner" != "$name" ]]; then
            conflicts+="    ${name}: GID ${uid} already belongs to group '${owner}'"$'\n'
        fi
        cur=$(getent group "$name" | cut -d: -f3 || true)
        if [[ -n "$cur" && "$cur" != "$uid" ]]; then
            conflicts+="    ${name}: a group named '${name}' exists with GID ${cur}, not ${uid}"$'\n'
        fi
    done <<< "$TAC_USERS"

    if [[ -n "$mismatches" ]]; then
        warn "Existing accounts whose UID differs from the one tacctl assigned:"
        printf '%s' "$mismatches" >&2
        cat >&2 <<'TXT'
  They are adopted as they are. To make them consistent, either
    - renumber the account on this host (user logged out, as root):
        usermod -u <uid> <user> && groupmod -g <uid> <user>
        find / -xdev \( -uid <old> -o -gid <old> \) -exec chown -h <user>:<user> {} +
    - or make this host's number the assigned one (if no other host has the user yet):
        tacctl config linux uid <user> <uid-on-this-host>
TXT
    fi

    [[ -n "$conflicts" ]] || return 0
    if [[ "$ALLOW_UID_MISMATCH" == "1" ]]; then
        warn "UID/GID conflicts accepted (--allow-uid-mismatch); these users get this host's next free number:"
        printf '%s' "$conflicts" >&2
        return 0
    fi
    echo "[ERROR] Cannot give these users their assigned UID/GID on this host:" >&2
    printf '%s' "$conflicts" >&2
    cat >&2 <<'TXT'
  Nothing was changed. Options:
    1. Free the number on this host by renumbering the account or group that holds it:
         usermod -u <new-uid> <other-user>     (or: groupmod -g <new-gid> <other-group>)
         find / -xdev \( -uid <old> -o -gid <old> \) -exec chown -h <other-user> {} +
    2. Assign the tacctl user a number that is free on every host, then re-run:
         tacctl config linux uid <user> <new-uid>
       (hosts that already have the account keep the old number until renumbered)
    3. Accept a different number on this host only:
         tacctl host enroll|sync ... --allow-uid-mismatch
       (or run this script with --allow-uid-mismatch)
TXT
    exit 1
}

# --- Adoption ------------------------------------------------------------------
# An account that already exists under a TACACS+ user's name is only taken
# over when the operator names it with --adopt: a matching name does not
# prove it is the same person. Accounts this script created or adopted on
# an earlier run need no flag.
PRIVILEGED_GROUPS="sudo wheel admin adm root docker lxd libvirt disk shadow"

check_adoption() {
    local name _rest unconfirmed=""
    while IFS=: read -r name _rest; do
        [[ -n "$name" ]] || continue
        getent passwd "$name" >/dev/null || continue
        if grep -qxF "$name" "$STATE_DIR/created" "$STATE_DIR/adopted"; then continue; fi
        if [[ ",${ADOPT}," == *",${name},"* ]]; then continue; fi
        unconfirmed+=" ${name}"
    done <<< "$TAC_USERS"
    [[ -n "$unconfirmed" ]] || return 0
    echo "[ERROR] These TACACS+ users already have a local account on this host that tacctl did not create:${unconfirmed}" >&2
    cat >&2 <<'TXT'
  Nothing was changed. A matching name does not prove it is the same person. Options:
    1. It is the same person: take the account over, keeping its UID, password, files and groups:
         tacctl host enroll|sync ... --adopt <name>[,<name>...]
       (or run this script with --adopt <name>[,<name>...])
    2. It is someone or something else: rename the tacctl user (tacctl user rename <old> <new>),
       or keep the user off this host (tacctl user scope <name> remove <scope>).
    3. The local account is obsolete: remove or rename it on this host, then re-run.
TXT
    exit 1
}

# Local groups that grant rights regardless of the TACACS+ tier.
privileged_groups_of() {
    local g found="" groups
    groups=" $(id -nG "$1" 2>/dev/null) "
    for g in $PRIVILEGED_GROUPS; do
        if [[ "$groups" == *" $g "* ]]; then found+="${found:+, }$g"; fi
    done
    echo "$found"
}

check_adoption
check_ids

# --- pam_tacplus module --------------------------------------------------------
# Built from the embedded source tarball, before any account is created, so
# a host that cannot build is left as it was. A host that already has the
# module from this same tarball is not rebuilt.
build_dir=""
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
    if [[ -n "$build_dir" ]]; then rm -rf "$build_dir"; fi
}

# The installed module came from this tarball and all of its files are present.
module_current() {
    local path
    [[ -f "$STATE_DIR/module" && -s "$STATE_DIR/files" ]] || return 1
    [[ "$(cat "$STATE_DIR/module")" == "$TARBALL_SHA256" ]] || return 1
    while IFS= read -r path; do
        [[ -e "$path" ]] || return 1
    done < "$STATE_DIR/files"
    return 0
}

apt_install() {
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get install -y $1 >/dev/null
}

ensure_build_tools() {
    local need_pkgs=""
    if [[ "$CLIENT_TEST" == "1" ]]; then
        need_pkgs="${TACCTL_CLIENT_NEED_PKGS:-}"
    else
        command -v gcc  >/dev/null || need_pkgs+=" gcc"
        command -v make >/dev/null || need_pkgs+=" make"
        [[ -f /usr/include/security/pam_modules.h ]] || need_pkgs+=" libpam0g-dev"
    fi
    [[ -n "$need_pkgs" ]] || return 0
    info "Installing build packages:${need_pkgs}"
    if apt_install "$need_pkgs"; then return 0; fi
    # A stale package index is the usual cause: refresh it once and retry.
    warn "Package install failed; refreshing the package index and retrying."
    apt-get update >/dev/null || true
    apt_install "$need_pkgs" || die "Could not install the build packages:${need_pkgs}
        This host needs working package repositories to build pam_tacplus.
        Nothing was changed: no accounts created, PAM untouched."
}

install_module() {
    local multiarch lib_dir sec_dir="" d
    if module_current; then
        info "pam_tacplus is already installed from this source; not rebuilding."
        return 0
    fi
    ensure_build_tools

    if [[ "$CLIENT_TEST" == "1" ]]; then
        lib_dir="$STATE_DIR/lib"
        sec_dir="$lib_dir/security"
        mkdir -p "$sec_dir"
    else
        multiarch=$(gcc -print-multiarch 2>/dev/null || true)
        lib_dir="/usr/lib${multiarch:+/$multiarch}"
        for d in "$lib_dir/security" /usr/lib64/security /usr/lib/security /lib/security; do
            if [[ -f "$d/pam_unix.so" ]]; then sec_dir="$d"; break; fi
        done
        [[ -n "$sec_dir" ]] || die "Could not find the PAM module directory."
    fi

    if [[ -e "$lib_dir/libtac.so.5" ]] && ! grep -qxF "$lib_dir/libtac.so.5" "$STATE_DIR/files" 2>/dev/null; then
        die "$lib_dir/libtac.so.5 already exists and was not installed by tacctl. Remove the other libtac first."
    fi

    info "Building pam_tacplus (this takes a minute)..."
    if [[ "$CLIENT_TEST" == "1" ]]; then
        mkdir -p "$build_dir/stage$sec_dir"
        touch "$build_dir/stage$lib_dir/libtac.so.5.0.0" "$build_dir/stage$sec_dir/pam_tacplus.so"
    else
        sed -n '/^__TARBALL__$/,$p' "$0" | tail -n +2 | base64 -d > "$build_dir/src.tar.gz"
        echo "${TARBALL_SHA256}  $build_dir/src.tar.gz" | sha256sum -c --quiet \
            || die "Embedded pam_tacplus tarball failed its checksum."
        tar -C "$build_dir" -xzf "$build_dir/src.tar.gz"
        (
            cd "$build_dir"/pam_tacplus-*/
            ./configure --prefix=/usr --libdir="$lib_dir" --enable-pamdir="$sec_dir" >"$build_dir/build.log" 2>&1
            make >>"$build_dir/build.log" 2>&1
            make install DESTDIR="$build_dir/stage" >>"$build_dir/build.log" 2>&1
        ) || { tail -20 "$build_dir/build.log" >&2; die "pam_tacplus build failed."; }
    fi

    install -m 0644 "$build_dir/stage$lib_dir/libtac.so.5.0.0" "$lib_dir/libtac.so.5.0.0"
    ln -sf libtac.so.5.0.0 "$lib_dir/libtac.so.5"
    install -m 0644 "$build_dir/stage$sec_dir/pam_tacplus.so" "$sec_dir/pam_tacplus.so"
    ldconfig
    {
        echo "$lib_dir/libtac.so.5.0.0"
        echo "$lib_dir/libtac.so.5"
        echo "$sec_dir/pam_tacplus.so"
    } > "$STATE_DIR/files"
    echo "$TARBALL_SHA256" > "$STATE_DIR/module"
}

if [[ "$ACCOUNTS_ONLY" != "1" ]]; then
    for svc in sshd sudo; do
        [[ -f "$PAM_DIR/$svc" ]] || die "$PAM_DIR/$svc not found."
        if ! grep -qE '^@include[[:space:]]+(common-auth|tacctl-auth)[[:space:]]*$' "$PAM_DIR/$svc"; then
            die "$PAM_DIR/$svc has no '@include common-auth' line; refusing to edit an unfamiliar PAM layout."
        fi
    done
    build_dir=$(mktemp -d)
    trap cleanup EXIT
    install_module
fi

# --- Accounts and groups -------------------------------------------------------
sync_accounts() {
    local g name tier uid managed member priv pw home still
    for g in "$G_USERS" tac-readonly tac-operator tac-superuser; do
        getent group "$g" >/dev/null || groupadd "$g"
    done

    while IFS=: read -r name tier uid; do
        [[ -n "$name" ]] || continue
        if getent passwd "$name" >/dev/null; then
            if ! grep -qxF "$name" "$STATE_DIR/created" "$STATE_DIR/adopted"; then
                echo "$name" >> "$STATE_DIR/adopted"
                info "Adopted existing account '${name}' (UID, local password, files and groups left as they are)."
                priv=$(privileged_groups_of "$name")
                if [[ -n "$priv" ]]; then
                    warn "'${name}' is in local group(s): ${priv}. Those rights stay whatever the TACACS+ tier (${tier}) is."
                fi
            fi
        else
            # New accounts get a locked password: TACACS+ is their only password.
            # UID and primary GID are the same number on every host. The
            # fallback is only reachable with --allow-uid-mismatch.
            if id_is_free "$name" "$uid"; then
                getent group "$name" >/dev/null || groupadd -g "$uid" "$name"
                useradd -m -u "$uid" -g "$name" -s /bin/bash -c "TACACS+ user (tacctl)" "$name"
            else
                useradd -m -s /bin/bash -c "TACACS+ user (tacctl)" "$name"
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
            # Adopted (or hand-added) account: not tacctl's to lock.
            pw=$(getent shadow "$member" 2>/dev/null | cut -d: -f2 || true)
            home=$(getent passwd "$member" | cut -d: -f6 || true)
            still="no local password"
            if [[ -n "$pw" && "$pw" != '!'* && "$pw" != '*'* ]]; then still="local password works"; fi
            if [[ -s "$home/.ssh/authorized_keys" ]]; then still+=", SSH key present"; fi
            priv=$(privileged_groups_of "$member")
            warn "'${member}' is no longer a TACACS+ user here but its local account was NOT disabled (${still}${priv:+; groups: $priv})."
            warn "  To block it: usermod -L -e 1 ${member}"
            sed -i "/^${member}\$/d" "$STATE_DIR/adopted"
        fi
    done
}

sync_accounts
if [[ "$ACCOUNTS_ONLY" == "1" ]]; then
    info "Accounts synced for scope '${TAC_SCOPE}'."
    exit 0
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
