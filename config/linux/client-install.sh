# --- tacctl Linux client: install / account sync -------------------------------
# Body of the script emitted by 'tacctl config linux script'. tacctl prepends
# a header that sets TAC_METHOD, TAC_SERVER, TAC_PORT, TAC_SECRET, TAC_SCOPE
# and TAC_USERS. TAC_METHOD picks the PAM module the host authenticates
# through; accounts, tiers, sudo and the fallback to local passwords are the
# same for both:
#
#   tacplus  pam_tacplus, which tacctl ships itself. The header also sets
#            TARBALL_SHA256 (plus PREBUILT_SHA256 and PREBUILT_FOR when a
#            prebuilt module is included), and the pam_tacplus source tarball
#            (base64) follows the __TARBALL__ marker, then the prebuilt
#            module after __PREBUILT__.
#   radius   pam_radius_auth from the distribution's package
#            (libpam-radius-auth; pam_radius from EPEL on the RHEL family).
#            The header also sets TAC_ACCT_PORT; nothing is appended.
#
# What each method needs is in the functions named <concern>_<method> below;
# everything else is shared. Run as root on the target host:
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
XDG_DIR="${TACCTL_CLIENT_XDG:-/etc/xdg}"
# sudo-i is the service 'sudo -i' uses; where it exists it has its own copy
# of the includes (Debian) or simply includes sudo (RHEL family). sddm and
# gdm-password are the graphical logins; GNOME's lock screen also unlocks
# through gdm-password. Files a host does not have are skipped.
PAM_SERVICES="sshd sudo sudo-i login sddm gdm-password"
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

# pam_radius_auth reads its server and shared secret from a file. It sits in
# /etc, not in $STATE_DIR: under SELinux sshd and login may read etc_t files
# but nothing below /var/lib. (The test suite never touches /etc.)
RADIUS_CONF="${TACCTL_CLIENT_RADIUS_CONF:-/etc/tacctl-pam_radius.conf}"
if [[ "$CLIENT_TEST" == "1" && -z "${TACCTL_CLIENT_RADIUS_CONF:-}" ]]; then
    RADIUS_CONF="$STATE_DIR/pam_radius.conf"
fi

# Debian/Ubuntu and RHEL-family hosts differ in package tool and in how the
# PAM service files pull in the shared stack.
if [[ "$CLIENT_TEST" == "1" && -n "${TACCTL_CLIENT_FAMILY:-}" ]]; then
    FAMILY="$TACCTL_CLIENT_FAMILY"
elif command -v apt-get >/dev/null; then
    FAMILY="debian"
elif command -v dnf >/dev/null || command -v yum >/dev/null; then
    FAMILY="rhel"
else
    die "Only Debian/Ubuntu and RHEL-family hosts are supported (no apt-get, dnf or yum here)."
fi
# RHEL family: the shared stacks the service files include.
RHEL_STACK='(password-auth|system-auth)'

# The method, and what messages, account names and comments call it.
TAC_METHOD="${TAC_METHOD:-tacplus}"
case "$TAC_METHOD" in
    tacplus) PROTO="TACACS+"; OTHER_METHOD="radius" ;;
    radius)  PROTO="RADIUS";  OTHER_METHOD="tacplus" ;;
    *) die "Unknown method '${TAC_METHOD}' (tacplus or radius)." ;;
esac

# Names of the users this script manages, one per line.
tac_user_names() {
    local name _rest
    while IFS=: read -r name _rest; do
        if [[ -n "$name" ]]; then echo "$name"; fi
    done <<< "$TAC_USERS"
    return 0
}

# A local administrator who does not depend on the server: root or a member of
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
    die "No local administrator with a usable password exists outside the ${PROTO} user list.
        Every sudo-capable account would depend on the ${PROTO} server. Give one local
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
# An account that already exists under a tacctl user's name is only taken
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
    echo "[ERROR] These ${PROTO} users already have a local account on this host that tacctl did not create:${unconfirmed}" >&2
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

# Local groups that grant rights regardless of the tier.
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

# --- PAM module ----------------------------------------------------------------
# Installed before any account is created, so a host that cannot get the
# module is left as it was (on a host switching methods: still working with
# the method it had).
#
# tacplus: 'tacctl host enroll' normally embeds a module built on the server
# for this OS release; otherwise, or if that one does not load here, it is
# compiled from the embedded source tarball. A host that already has the
# module from this same source is left alone.
#
# radius: the distribution's package. On the RHEL family that package is in
# EPEL, which is enabled here when the host does not have it.
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
    # Nothing refers to the RADIUS server file any more; it holds the secret.
    rm -f "$RADIUS_CONF"
    warn "Install failed: PAM service files restored from backup, ${PROTO} not enabled."
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

# Extra dnf options for pkg_install (the EPEL repository, when pam_radius
# needs it).
PKG_OPTS=""
pkg_install() {
    if [[ "$FAMILY" == "rhel" ]]; then
        # shellcheck disable=SC2086
        "$(command -v dnf || command -v yum)" install -y -q $PKG_OPTS $1 >/dev/null
    else
        # shellcheck disable=SC2086
        DEBIAN_FRONTEND=noninteractive apt-get install -y $1 >/dev/null
    fi
}

pkg_refresh() {
    if [[ "$FAMILY" == "rhel" ]]; then
        "$(command -v dnf || command -v yum)" -q makecache >/dev/null || true
    else
        apt-get update >/dev/null || true
    fi
}

# pkg_ensure <packages> <purpose>: install, retrying once after an index refresh.
pkg_ensure() {
    local pkgs="$1" purpose="$2"
    info "Installing ${purpose}:${pkgs}"
    if pkg_install "$pkgs"; then return 0; fi
    # A stale package index is the usual cause: refresh it once and retry.
    warn "Package install failed; refreshing the package index and retrying."
    pkg_refresh
    pkg_install "$pkgs" || die "Could not install the ${purpose}:${pkgs}
        This host needs working package repositories to build pam_tacplus.
        Nothing was changed: no accounts created, PAM untouched."
}

ensure_build_tools() {
    local need_pkgs="" pam_dev="libpam0g-dev"
    if [[ "$FAMILY" == "rhel" ]]; then pam_dev="pam-devel"; fi
    if [[ "$CLIENT_TEST" == "1" ]]; then
        need_pkgs="${TACCTL_CLIENT_NEED_PKGS:-}"
    else
        command -v gcc  >/dev/null || need_pkgs+=" gcc"
        command -v make >/dev/null || need_pkgs+=" make"
        [[ -f /usr/include/security/pam_modules.h ]] || need_pkgs+=" ${pam_dev}"
    fi
    [[ -n "$need_pkgs" ]] || return 0
    pkg_ensure "$need_pkgs" "build packages"
}

# Where this host keeps PAM modules; shared libraries go one level up.
# Found without a compiler, since a prebuilt module needs none.
pam_module_dir() {
    local d
    for d in "/usr/lib/$(uname -m)-linux-gnu/security" /usr/lib/*/security \
             /usr/lib64/security /usr/lib/security /lib/security; do
        if [[ -f "$d/pam_unix.so" ]]; then echo "$d"; return 0; fi
    done
    return 1
}

# Unpack the module the tacctl server built for this OS release into
# $build_dir/out. Fails (so the caller compiles instead) when there is
# none, or when it does not load against this host's libraries.
unpack_prebuilt() {
    local out="$build_dir/out"
    [[ -n "${PREBUILT_SHA256:-}" ]] || return 1
    sed -n '/^__PREBUILT__$/,$p' "$0" | tail -n +2 | base64 -d > "$build_dir/prebuilt.tar.gz"
    if ! echo "${PREBUILT_SHA256}  $build_dir/prebuilt.tar.gz" | sha256sum -c --quiet 2>/dev/null; then
        warn "The prebuilt pam_tacplus failed its checksum; building on this host instead."
        return 1
    fi
    rm -rf "$out"; mkdir -p "$out"
    tar -C "$out" --no-same-owner -xzf "$build_dir/prebuilt.tar.gz" libtac.so.5.0.0 pam_tacplus.so
    ln -s libtac.so.5.0.0 "$out/libtac.so.5"
    if LD_LIBRARY_PATH="$out" ldd "$out/pam_tacplus.so" 2>&1 | grep -q 'not found'; then
        warn "The prebuilt pam_tacplus (${PREBUILT_FOR:-unknown}) does not load on this host; building here instead."
        return 1
    fi
    return 0
}

compile_module() {
    local lib_dir="$1" sec_dir="$2" out="$build_dir/out"
    ensure_build_tools
    info "Building pam_tacplus on this host (this takes a minute)..."
    rm -rf "$out"; mkdir -p "$out"
    if [[ "$CLIENT_TEST" == "1" ]]; then
        touch "$out/libtac.so.5.0.0" "$out/pam_tacplus.so"
        return 0
    fi
    sed -n '/^__TARBALL__$/,/^__PREBUILT__$/p' "$0" | sed '1d;/^__PREBUILT__$/d' | base64 -d > "$build_dir/src.tar.gz"
    echo "${TARBALL_SHA256}  $build_dir/src.tar.gz" | sha256sum -c --quiet \
        || die "Embedded pam_tacplus tarball failed its checksum."
    tar -C "$build_dir" -xzf "$build_dir/src.tar.gz"
    (
        cd "$build_dir"/pam_tacplus-*/
        ./configure --prefix=/usr --libdir="$lib_dir" --enable-pamdir="$sec_dir" >"$build_dir/build.log" 2>&1
        make >>"$build_dir/build.log" 2>&1
        make install DESTDIR="$build_dir/stage" >>"$build_dir/build.log" 2>&1
    ) || { tail -20 "$build_dir/build.log" >&2; die "pam_tacplus build failed."; }
    cp "$build_dir/stage$lib_dir/libtac.so.5.0.0" "$build_dir/stage$sec_dir/pam_tacplus.so" "$out/"
}

install_module_tacplus() {
    local lib_dir sec_dir
    if module_current; then
        info "pam_tacplus is already installed from this source; not rebuilding."
        return 0
    fi
    # Minimal RHEL-family installs come without tar.
    if [[ "$CLIENT_TEST" != "1" ]] && ! command -v tar >/dev/null; then
        pkg_ensure " tar" "packages needed to unpack the module"
    fi

    if [[ "$CLIENT_TEST" == "1" ]]; then
        sec_dir="$STATE_DIR/lib/security"
        mkdir -p "$sec_dir"
    else
        sec_dir=$(pam_module_dir) || die "Could not find the PAM module directory."
    fi
    lib_dir="${sec_dir%/security}"

    if [[ -e "$lib_dir/libtac.so.5" ]] && ! grep -qxF "$lib_dir/libtac.so.5" "$STATE_DIR/files" 2>/dev/null; then
        die "$lib_dir/libtac.so.5 already exists and was not installed by tacctl. Remove the other libtac first."
    fi

    if unpack_prebuilt; then
        info "Installing pam_tacplus built on the tacctl server for ${PREBUILT_FOR:-this OS} (nothing is compiled here)."
    else
        compile_module "$lib_dir" "$sec_dir"
    fi

    install -m 0644 "$build_dir/out/libtac.so.5.0.0" "$lib_dir/libtac.so.5.0.0"
    ln -sf libtac.so.5.0.0 "$lib_dir/libtac.so.5"
    install -m 0644 "$build_dir/out/pam_tacplus.so" "$sec_dir/pam_tacplus.so"
    ldconfig
    {
        echo "$lib_dir/libtac.so.5.0.0"
        echo "$lib_dir/libtac.so.5"
        echo "$sec_dir/pam_tacplus.so"
    } > "$STATE_DIR/files"
    echo "$TARBALL_SHA256" > "$STATE_DIR/module"
}

# Where pam_radius_auth.so is, or would be once its package is installed.
radius_module_path() {
    local sec_dir
    if [[ "$CLIENT_TEST" == "1" ]]; then
        sec_dir="$STATE_DIR/lib/security"
    else
        sec_dir=$(pam_module_dir) || return 1
    fi
    echo "$sec_dir/pam_radius_auth.so"
}

# The packaged module's version, as the package manager reports it.
radius_module_version() {
    if [[ "$CLIENT_TEST" == "1" ]]; then
        echo "${TACCTL_CLIENT_RADIUS_VERSION:-}"
    elif [[ "$FAMILY" == "rhel" ]]; then
        rpm -q --qf '%{VERSION}-%{RELEASE}' pam_radius 2>/dev/null || true
    else
        dpkg-query -W -f '${Version}' libpam-radius-auth 2>/dev/null || true
    fi
}

# Packages this script installed are noted, so the removal script can name
# what it leaves behind.
note_package() {
    grep -qxF "$1" "$STATE_DIR/packages" 2>/dev/null || echo "$1" >> "$STATE_DIR/packages"
}

# RHEL family: pam_radius is not in the distribution's own repositories but
# in EPEL (EL8 and EL9: 2.0.0, EL10: 3.0.0). It needs nothing from CRB or
# PowerTools. AlmaLinux, Rocky and CentOS Stream carry the epel-release
# package in a repository they enable by default; RHEL and Oracle Linux do
# not, and there the release package comes from the EPEL project's own URL.
# Sets EPEL_ADDED=1 when this run installed epel-release, so a failure
# afterwards can take it out again.
EPEL_ADDED=0
ensure_epel() {
    local dnf major
    dnf=$(command -v dnf || command -v yum)
    if "$dnf" -q list pam_radius >/dev/null 2>&1; then return 0; fi
    if ! rpm -q epel-release >/dev/null 2>&1; then
        info "pam_radius is packaged in EPEL, which this host does not have: installing epel-release."
        "$dnf" install -y -q epel-release >/dev/null 2>&1 || true
        if ! rpm -q epel-release >/dev/null 2>&1; then
            major=$(rpm -E '%{?rhel}' 2>/dev/null || true)
            if [[ "$major" =~ ^[0-9]+$ ]]; then
                "$dnf" install -y -q "https://dl.fedoraproject.org/pub/epel/epel-release-latest-${major}.noarch.rpm" >/dev/null 2>&1 || true
            fi
        fi
        rpm -q epel-release >/dev/null 2>&1 || die "Could not enable EPEL on this host (neither 'dnf install epel-release' nor the
        release package from dl.fedoraproject.org worked). pam_radius is an EPEL package:
        give the host that repository, or install pam_radius by hand, then re-run.
        Nothing was changed: no accounts created, PAM untouched."
        EPEL_ADDED=1
    fi
    # An EPEL the administrator keeps disabled is used for this one package only.
    PKG_OPTS="--enablerepo=epel"
}

install_module_radius() {
    local module pkg="libpam-radius-auth" hint="On Ubuntu it is in the 'universe' component."
    module=$(radius_module_path) || die "Could not find the PAM module directory."
    if [[ -f "$module" ]]; then
        info "pam_radius_auth is already installed; nothing to install."
        return 0
    fi
    if [[ "$FAMILY" == "rhel" ]]; then
        pkg="pam_radius"
        hint="It comes from EPEL."
        ensure_epel
    fi
    info "Installing the RADIUS PAM module: ${pkg}"
    if ! pkg_install " ${pkg}"; then
        # A stale package index is the usual cause: refresh it once and retry.
        warn "Package install failed; refreshing the package index and retrying."
        pkg_refresh
        if ! pkg_install " ${pkg}"; then
            if [[ "$EPEL_ADDED" == "1" ]]; then
                "$(command -v dnf || command -v yum)" remove -y -q epel-release >/dev/null 2>&1 || true
            fi
            die "Could not install the RADIUS PAM module: ${pkg}
        This host needs a working package repository that carries it. ${hint}
        Nothing was changed: no accounts created, PAM untouched."
        fi
    fi
    if [[ "$CLIENT_TEST" == "1" ]]; then
        mkdir -p "${module%/*}"
        touch "$module"
    fi
    [[ -f "$module" ]] || die "Package ${pkg} is installed but ${module} is missing.
        Nothing was changed: no accounts created, PAM untouched."
    note_package "$pkg"
    if [[ "$EPEL_ADDED" == "1" ]]; then note_package "epel-release"; fi
}

# remove_method_artifacts <method>: take out what the install of <method>
# put on this host apart from the PAM files, which the caller has rewritten:
# module files, the file with the secret, the SELinux module, the state
# files. Safe to run when there is nothing. Packages are left installed.
remove_method_artifacts() {
    local path
    case "$1" in
        tacplus)
            if [[ -f "$STATE_DIR/files" ]]; then
                while IFS= read -r path; do
                    if [[ "$path" == /usr/lib/* || "$path" == /usr/lib64/* || "$path" == /lib/* \
                        || ( "$CLIENT_TEST" == "1" && "$path" == "$STATE_DIR"/lib/* ) ]]; then
                        rm -f "$path"
                    fi
                done < "$STATE_DIR/files"
                ldconfig
            fi
            rm -f "$STATE_DIR/files" "$STATE_DIR/module"
            if [[ -f "$STATE_DIR/tacctl_pam.cil" ]]; then
                if command -v semodule >/dev/null; then semodule -r tacctl_pam 2>/dev/null || true; fi
                rm -f "$STATE_DIR/tacctl_pam.cil"
            fi
            ;;
        radius)
            rm -f "$RADIUS_CONF"
            if [[ -f "$STATE_DIR/tacctl_pam_radius.cil" ]]; then
                if command -v semodule >/dev/null; then semodule -r tacctl_pam_radius 2>/dev/null || true; fi
                rm -f "$STATE_DIR/tacctl_pam_radius.cil"
            fi
            ;;
    esac
}

if [[ "$ACCOUNTS_ONLY" != "1" ]]; then
    for svc in sshd sudo; do
        [[ -f "$PAM_DIR/$svc" ]] || die "$PAM_DIR/$svc not found."
        if [[ "$FAMILY" == "rhel" ]]; then
            if ! grep -qE "^auth[[:space:]]+(substack|include)[[:space:]]+(${RHEL_STACK}|tacctl-auth)[[:space:]]*\$" "$PAM_DIR/$svc"; then
                die "$PAM_DIR/$svc has no 'auth substack|include password-auth|system-auth' line; refusing to edit an unfamiliar PAM layout."
            fi
        elif ! grep -qE '^@include[[:space:]]+(common-auth|tacctl-auth)[[:space:]]*$' "$PAM_DIR/$svc"; then
            die "$PAM_DIR/$svc has no '@include common-auth' line; refusing to edit an unfamiliar PAM layout."
        fi
    done
    build_dir=$(mktemp -d)
    trap cleanup EXIT
    "install_module_${TAC_METHOD}"
fi

# --- Accounts and groups -------------------------------------------------------
sync_accounts() {
    local g name tier uid managed member priv pw home still gecos
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
                    warn "'${name}' is in local group(s): ${priv}. Those rights stay whatever the ${PROTO} tier (${tier}) is."
                fi
            elif grep -qxF "$name" "$STATE_DIR/created"; then
                # Earlier versions gave every account the same full name,
                # which is all a graphical login screen shows; and a host
                # that switched methods carries the other method's name.
                gecos=$(getent passwd "$name" | cut -d: -f5)
                case "$gecos" in
                    "${name} (${PROTO})") ;;
                    "TACACS+ user (tacctl)"|"${name} (TACACS+)"|"${name} (RADIUS)")
                        usermod -c "${name} (${PROTO})" "$name" ;;
                esac
            fi
        else
            # New accounts get a locked password: the server's is their only
            # password. The full name carries the login name, since graphical
            # login screens list accounts by full name.
            # UID and primary GID are the same number on every host. The
            # fallback is only reachable with --allow-uid-mismatch.
            if id_is_free "$name" "$uid"; then
                getent group "$name" >/dev/null || groupadd -g "$uid" "$name"
                useradd -m -u "$uid" -g "$name" -s /bin/bash -c "${name} (${PROTO})" "$name"
            else
                useradd -m -s /bin/bash -c "${name} (${PROTO})" "$name"
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
            info "'${member}' is no longer a ${PROTO} user here: account expired, files kept."
        else
            # Adopted (or hand-added) account: not tacctl's to lock.
            pw=$(getent shadow "$member" 2>/dev/null | cut -d: -f2 || true)
            home=$(getent passwd "$member" | cut -d: -f6 || true)
            still="no local password"
            if [[ -n "$pw" && "$pw" != '!'* && "$pw" != '*'* ]]; then still="local password works"; fi
            if [[ -s "$home/.ssh/authorized_keys" ]]; then still+=", SSH key present"; fi
            priv=$(privileged_groups_of "$member")
            warn "'${member}' is no longer a ${PROTO} user here but its local account was NOT disabled (${still}${priv:+; groups: $priv})."
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
# Only members of tac-users are sent to the server; everyone else skips
# straight to the distribution's own stack. A reject from the server is
# final. An unreachable server falls through to the local password, which
# only adopted accounts have.
#
# Each method sets the module lines of the three tacctl files: pam_auth,
# pam_account and pam_session; an empty one leaves that phase to the
# distribution's stack alone.
gate="pam_succeed_if.so quiet user ingroup ${G_USERS}"

# pam_tacplus takes the shared secret as a module argument, so these files
# are root-only. sshd, sudo and login all read PAM config as root.
# Authorization is only possible in the process that did the TACACS+
# authentication; for SSH-key logins the module reports auth_err, which is
# ignored here. Removed or disabled users are handled by account sync.
pam_lines_tacplus() {
    local tac_args
    if [[ "$TAC_SERVER" == *:* ]]; then
        tac_args="server=[${TAC_SERVER}]:${TAC_PORT}"
    else
        tac_args="server=${TAC_SERVER}:${TAC_PORT}"
    fi
    tac_args+=" secret=${TAC_SECRET} timeout=3 login=pap service=shell protocol=ssh"
    pam_auth="auth    [success=done authinfo_unavail=ignore default=die]   pam_tacplus.so ${tac_args}"
    pam_account="account [success=ok perm_denied=die default=ignore]          pam_tacplus.so ${tac_args}"
    pam_session="session optional                                             pam_tacplus.so ${tac_args}"
}

# pam_radius_auth, as observed on the packaged 2.0.0, 2.0.1 and 3.0.0
# (docs/radius-notes.md, "Linux hosts"):
#
#   Access-Accept                          PAM_SUCCESS            -> done
#   Access-Reject (wrong password, user    PAM_AUTH_ERR           -> die
#     not in the scope, unknown, disabled)
#   no answer after every try, an answer   PAM_AUTHINFO_UNAVAIL   -> ignore:
#     that fails verification (wrong                                 on to the
#     secret), server name not resolvable                            local stack
#   server file missing or unreadable      PAM_ABORT              -> die
#
# so the control line is the one pam_tacplus has. The server and the secret
# are in $RADIUS_CONF (root-only), never on a PAM line. The port is always
# written: without one the module looks up 'radius' in /etc/services, which a
# minimal host may not have.
#
# Timing. The module waits at least 3 seconds per try whatever the file says
# and 'retry=1' gives two tries: a server that does not answer costs a member
# of tac-users 6 seconds before the local password is asked for. Everyone
# else never reaches the module. The session line sends one accounting
# packet at login and one at logout, one try each (3 seconds when the server
# is silent).
#
# account: the module has no account step that asks the server (2.0.x
# returns success without sending anything; 3.0.0 has none and PAM reports
# 'module is unknown'), so there is no line. What the server allows arrived
# with the Access-Accept; removed or disabled users are handled by account
# sync.
#
# session: accounting goes to the authentication port plus one, which the
# module cannot be told otherwise, and 2.0.1 (Ubuntu 24.04) sends
# Acct-Status-Type and its other integer attributes as garbage. In both
# cases the line is left out and the host sends no accounting.
RADIUS_TIMEOUT=3
RADIUS_RETRY=1
write_radius_conf() {
    local host="$TAC_SERVER" tmp
    if [[ "$host" == *:* ]]; then host="[${host}]"; fi
    # Written whole and moved into place: a login never sees half a file.
    tmp=$(mktemp "${RADIUS_CONF}.XXXXXX")
    cat > "$tmp" <<EOF
# Managed by tacctl (scope ${TAC_SCOPE}). Do not edit; re-run the install script.
# Holds the scope's shared secret: root only.
# server:port  secret  timeout
${host}:${TAC_PORT} ${TAC_SECRET} ${RADIUS_TIMEOUT}
EOF
    chmod 0600 "$tmp"
    if [[ "$CLIENT_TEST" != "1" ]]; then chown root:root "$tmp"; fi
    mv -f "$tmp" "$RADIUS_CONF"
}
pam_lines_radius() {
    local module version rad_args="conf=${RADIUS_CONF} retry=${RADIUS_RETRY}"
    module=$(radius_module_path)
    # Builds with the BlastRADIUS fix can insist that every answer carries a
    # Message-Authenticator, which FreeRADIUS 3.0.27 / 3.2.5 and later always
    # send. A module without the option would only log that it is unknown.
    if grep -q require_message_authenticator "$module" 2>/dev/null; then
        rad_args+=" require_message_authenticator"
    fi
    write_radius_conf
    pam_auth="auth    [success=done authinfo_unavail=ignore default=die]   pam_radius_auth.so ${rad_args}"
    pam_account=""
    pam_session=""
    version=$(radius_module_version)
    if [[ -z "${TAC_ACCT_PORT:-}" || "$TAC_ACCT_PORT" != "$((TAC_PORT + 1))" ]]; then
        info "No session accounting from this host: pam_radius_auth sends it to the authentication port plus one ($((TAC_PORT + 1))), and the server's accounting listener is ${TAC_ACCT_PORT:-not set}."
    elif [[ "$version" == 2.0.1* ]]; then
        info "No session accounting from this host: pam_radius_auth ${version} sends malformed accounting records. Logins are still in the server's authentication log."
    else
        pam_session="session optional                                             pam_radius_auth.so conf=${RADIUS_CONF}"
    fi
}

pam_auth="" pam_account="" pam_session=""
pam_edit_started=1
"pam_lines_${TAC_METHOD}"

write_pam() {
    local file="$PAM_DIR/$1"
    install -m 0600 -o root -g root /dev/null "$file"
    cat > "$file"
}
# On Debian the tacctl files replace the service's @include of common-auth
# and common-account and pull those in themselves. On the RHEL family the
# service keeps its own line for password-auth/system-auth and a tacctl
# 'include' line is put in front of it; 'include' splices the lines into
# the service's stack, so the skip, 'done' and 'die' actions behave the
# same in both layouts.
tail_auth="@include common-auth"
tail_account="@include common-account"
if [[ "$FAMILY" == "rhel" ]]; then tail_auth=""; tail_account=""; fi
pam_header="# Managed by tacctl (scope ${TAC_SCOPE}). Do not edit; re-run the install script."
write_pam tacctl-auth <<EOF
${pam_header}
auth    [success=ok default=1]                               ${gate}
${pam_auth}
${tail_auth}
EOF
# The gate skips exactly one line, so it is only written in front of one.
{
    echo "$pam_header"
    if [[ -n "$pam_account" ]]; then
        echo "account [success=ok default=1]                               ${gate}"
        echo "$pam_account"
    fi
    echo "$tail_account"
} | write_pam tacctl-account
{
    echo "$pam_header"
    if [[ -n "$pam_session" ]]; then
        echo "session [success=ok default=1]                               ${gate}"
        echo "$pam_session"
    fi
} | write_pam tacctl-session

for svc in $PAM_SERVICES; do
    f="$PAM_DIR/$svc"
    [[ -f "$f" ]] || continue
    # Keep the first backup: it is the pre-tacctl original.
    [[ -f "$STATE_DIR/backup/$svc" ]] || cp -p "$f" "$STATE_DIR/backup/$svc"
    if [[ "$FAMILY" == "rhel" ]]; then
        if ! grep -qE '^auth[[:space:]]+include[[:space:]]+tacctl-auth$' "$f"; then
            sed -i -E "0,/^auth[[:space:]]+(substack|include)[[:space:]]+${RHEL_STACK}[[:space:]]*\$/s//auth       include      tacctl-auth\n&/" "$f"
        fi
        if ! grep -qE '^account[[:space:]]+include[[:space:]]+tacctl-account$' "$f"; then
            sed -i -E "0,/^account[[:space:]]+(substack|include)[[:space:]]+${RHEL_STACK}[[:space:]]*\$/s//account    include      tacctl-account\n&/" "$f"
        fi
        if [[ "$svc" != sudo* ]] && ! grep -qE '^session[[:space:]]+include[[:space:]]+tacctl-session$' "$f"; then
            sed -i -E "0,/^session[[:space:]]+(substack|include)[[:space:]]+${RHEL_STACK}[[:space:]]*\$/s//&\nsession    include      tacctl-session/" "$f"
        fi
        continue
    fi
    sed -i -E \
        -e 's/^@include[[:space:]]+common-auth[[:space:]]*$/@include tacctl-auth/' \
        -e 's/^@include[[:space:]]+common-account[[:space:]]*$/@include tacctl-account/' "$f"
    if [[ "$svc" != sudo* ]] && ! grep -q '^@include tacctl-session$' "$f"; then
        sed -i -E '/^@include[[:space:]]+common-session[[:space:]]*$/a @include tacctl-session' "$f"
    fi
done
for svc in sshd sudo; do
    grep -qE '^(@include|auth[[:space:]]+include[[:space:]]+)[[:space:]]*tacctl-auth$' "$PAM_DIR/$svc" \
        || die "Failed to edit $PAM_DIR/$svc."
    grep -qE '^(@include|account[[:space:]]+include[[:space:]]+)[[:space:]]*tacctl-account$' "$PAM_DIR/$svc" \
        || die "Failed to edit $PAM_DIR/$svc."
done

# --- SELinux -------------------------------------------------------------------
# Failure is reported, not fatal: logins then behave as if the server were
# unreachable. Both modules are CIL text, so nothing has to be compiled.
#
# tacplus: sshd, login and (for confined users) sudo may not open a TACACS+
# connection on their own: RHEL's policy has no type for the port and only
# lets them through with the broad nis_enabled boolean. A small local
# module labels exactly the configured port and allows those three to
# connect to it.
selinux_tacplus() {
    cat > "$STATE_DIR/tacctl_pam.cil" <<CIL
(type tacctl_tacacs_port_t)
(roletype object_r tacctl_tacacs_port_t)
(typeattributeset port_type tacctl_tacacs_port_t)
(portcon tcp ${TAC_PORT} (system_u object_r tacctl_tacacs_port_t ((s0) (s0))))
(optional tacctl_pam_sshd (allow sshd_t tacctl_tacacs_port_t (tcp_socket (name_connect))))
(optional tacctl_pam_login (allow local_login_t tacctl_tacacs_port_t (tcp_socket (name_connect))))
(optional tacctl_pam_sudo (allow sudodomain tacctl_tacacs_port_t (tcp_socket (name_connect))))
CIL
    if semodule -i "$STATE_DIR/tacctl_pam.cil" 2>/dev/null; then
        info "SELinux: policy module tacctl_pam installed (sshd, login and sudo may connect to tcp/${TAC_PORT})."
    else
        warn "SELinux: could not install the tacctl_pam policy module; TACACS+ logins may be denied (check: ausearch -m avc -c sshd)."
    fi
    if [[ -f "$STATE_DIR/files" ]]; then
        # shellcheck disable=SC2046
        restorecon $(cat "$STATE_DIR/files") "$PAM_DIR"/tacctl-* 2>/dev/null || true
    fi
}

# radius: UDP has no connect permission and the port needs no label. The
# packaged module binds its socket to port 0 on the wildcard address, which
# asks for node_bind only (name_bind is not checked for port 0; the
# authlogin_radius boolean is for older modules that picked a port
# themselves). The EL8, EL9 and EL10 targeted policies give sshd and the
# display managers node_bind outright, but login and the sudo domains of
# confined users only through the kerberos_enabled or nis_enabled booleans:
# the module allows those two directly. The server file is etc_t, which
# every login program may read.
selinux_radius() {
    cat > "$STATE_DIR/tacctl_pam_radius.cil" <<'CIL'
(optional tacctl_pam_radius_login (allow local_login_t node_t (udp_socket (node_bind))))
(optional tacctl_pam_radius_sudo (allow sudodomain node_t (udp_socket (node_bind))))
CIL
    if semodule -i "$STATE_DIR/tacctl_pam_radius.cil" 2>/dev/null; then
        info "SELinux: policy module tacctl_pam_radius installed (login and sudo may open the socket pam_radius_auth uses; sshd already may)."
    else
        warn "SELinux: could not install the tacctl_pam_radius policy module; RADIUS logins may be denied (check: ausearch -m avc -c sshd; 'setsebool -P authlogin_radius on' is the policy's own switch)."
    fi
    restorecon "$RADIUS_CONF" "$PAM_DIR"/tacctl-* 2>/dev/null || true
}

if command -v selinuxenabled >/dev/null && selinuxenabled 2>/dev/null; then
    "selinux_${TAC_METHOD}"
fi

# --- sudo for superusers -------------------------------------------------------
sudoers_tmp=$(mktemp)
cat > "$sudoers_tmp" <<EOF
# Managed by tacctl. ${PROTO} superusers get full sudo (password required).
%tac-superuser ALL=(ALL:ALL) ALL
EOF
visudo -cf "$sudoers_tmp" >/dev/null || die "visudo rejected the sudoers drop-in."
install -m 0440 -o root -g root "$sudoers_tmp" "$SUDOERS_HOST_FILE"
rm -f "$sudoers_tmp"

pam_committed=1

# --- The other method ------------------------------------------------------------
# A host has one method. Whatever the other one left here goes now that the
# PAM files no longer use it: its module files or its server file with the
# secret, its SELinux module, its state. $STATE_DIR/method is absent on a
# host enrolled before there were two; that host has tacplus.
prev_method=""
if [[ -f "$STATE_DIR/method" ]]; then
    prev_method=$(cat "$STATE_DIR/method")
elif [[ -f "$STATE_DIR/installed" ]]; then
    prev_method="tacplus"
fi
remove_method_artifacts "$OTHER_METHOD"
if [[ "$prev_method" == "$OTHER_METHOD" ]]; then
    info "This host used ${OTHER_METHOD} before: its PAM lines, shared secret and module configuration were removed."
fi
echo "$TAC_METHOD" > "$STATE_DIR/method"
{
    echo "scope=${TAC_SCOPE}"
    echo "server=${TAC_SERVER}:${TAC_PORT}"
    echo "installed=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$STATE_DIR/installed"

# --- KDE Plasma: no screen lock for tacctl accounts ----------------------------
# KDE's lock screen authenticates as the logged-in user, not as root, so it
# cannot read the root-only files that hold the shared secret: a user who
# locked the screen could not unlock it. Plasma sources env/*.sh at session
# start; ours puts a locked-down config directory first for accounts this
# script created (full name ending in "(TACACS+)" or "(RADIUS)"). Other
# accounts keep theirs.
# Timeout=0 is what the settings page shows as "Never"; Autolock is what the
# locker itself obeys.
if [[ -f "$PAM_DIR/kde" || -d "$XDG_DIR/plasma-workspace" || ( "$CLIENT_TEST" != "1" && -f /usr/lib/pam.d/kde ) ]]; then
    mkdir -p "$XDG_DIR/tacctl" "$XDG_DIR/plasma-workspace/env"
    chmod 0755 "$XDG_DIR/tacctl"
    cat > "$XDG_DIR/tacctl/kscreenlockerrc" <<EOF
# Managed by tacctl. Applies to ${PROTO} accounts only.
[Daemon]
Autolock[\$i]=false
Timeout[\$i]=0
LockOnResume[\$i]=false
LockOnStart[\$i]=false
EOF
    cat > "$XDG_DIR/tacctl/kdeglobals" <<EOF
# Managed by tacctl. Applies to ${PROTO} accounts only.
[KDE Action Restrictions][\$i]
action/lock_screen=false
EOF
    cat > "$XDG_DIR/plasma-workspace/env/tacctl-nolock.sh" <<EOF
# Managed by tacctl. KDE's lock screen cannot check ${PROTO} passwords, so
# screen locking is switched off for ${PROTO} accounts.
case "\$(getent passwd "\$(id -un)" | cut -d: -f5)" in
    *"(${PROTO})") export XDG_CONFIG_DIRS="${XDG_DIR}/tacctl:\${XDG_CONFIG_DIRS:-/etc/xdg}" ;;
esac
EOF
    chmod 0644 "$XDG_DIR/tacctl/kscreenlockerrc" "$XDG_DIR/tacctl/kdeglobals" "$XDG_DIR/plasma-workspace/env/tacctl-nolock.sh"
    kde_nolock=1
fi

# --- Post-install checks -------------------------------------------------------
if [[ -f "$PAM_DIR/sddm" || -f "$PAM_DIR/gdm-password" ]]; then
    info "Graphical login (SDDM/GDM) uses ${PROTO} for these users. Their keyring or wallet is not unlocked automatically."
fi
if [[ "${kde_nolock:-0}" == "1" ]]; then
    info "KDE Plasma: screen locking is switched off for ${PROTO} accounts (the lock screen cannot check"
    info "  ${PROTO} passwords). It applies from their next login; a session locked anyway is unlocked"
    info "  from another login with: loginctl unlock-sessions"
fi
# TACACS+ is TCP: a connect shows whether the server is reachable. RADIUS is
# UDP and the server answers nothing but a valid request, so there is no
# probe: only a login shows it.
reachability_tacplus() {
    if ! timeout 4 bash -c "exec 3<>/dev/tcp/${TAC_SERVER}/${TAC_PORT}" 2>/dev/null; then
        warn "Cannot reach ${TAC_SERVER} port ${TAC_PORT} from this host. TACACS+ logins will fail until it is reachable."
    fi
}
reachability_radius() {
    info "RADIUS is UDP: whether ${TAC_SERVER} port ${TAC_PORT} answers this host only shows at a login. A server that does not answer costs a RADIUS user $((RADIUS_TIMEOUT * (RADIUS_RETRY + 1))) seconds per attempt."
}
"reachability_${TAC_METHOD}"
if command -v sshd >/dev/null; then
    sshd_conf=$(sshd -T 2>/dev/null || true)
    grep -qi '^usepam yes' <<< "$sshd_conf" \
        || warn "sshd has 'UsePAM no': SSH logins will not use ${PROTO}."
    grep -qi '^passwordauthentication yes' <<< "$sshd_conf" \
        || warn "sshd has 'PasswordAuthentication no': ${PROTO} users cannot log in over SSH with a password."
fi

info "${PROTO} authentication installed for scope '${TAC_SCOPE}' (server ${TAC_SERVER}:${TAC_PORT})."
info "Local administrators unaffected by ${PROTO}: $(local_admins | paste -sd' ')"
test_user="tacacs-user"
if [[ "$TAC_METHOD" == "radius" ]]; then test_user="radius-user"; fi
info "Keep this session open and test from a second one: ssh <${test_user}>@$(hostname)"
exit 0
