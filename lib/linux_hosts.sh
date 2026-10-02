# shellcheck shell=bash
# tacctl lib/linux_hosts.sh -- config linux (pam_tacplus client scripts, prebuilt modules) and host enroll/sync/unenroll
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# --- CONFIG LINUX (TACACS+ login for Linux hosts) ---
# Linux hosts authenticate through pam_tacplus. No distribution ships a
# usable build and upstream is archived, so tacctl pins one tag, prepares a
# self-contained source tarball once on the server ('config linux build'),
# and embeds it in a per-scope install script ('config linux script') that
# builds it on the target with only gcc, make and the PAM headers.
# 'host enroll' goes one better: it builds the module here, in a container
# of the target's OS release, and ships the binary so the target compiles
# nothing; the embedded source stays as the fallback. The script bodies
# live in config/linux/.
LINUX_DIR="${TACCTL_LINUX_DIR:-/var/lib/tacctl/linux}"
LINUX_SRC_DIR="${SCRIPT_DIR}/../config/linux"
LINUX_UID_FILE="${TACCTL_STATE_DIR}/linux-uids"
LINUX_UID_BASE=20000
PAM_TACPLUS_REPO="https://github.com/kravietz/pam_tacplus.git"
PAM_TACPLUS_TAG="v1.7.0"
PAM_TACPLUS_COMMIT="b1b7f5351eca07f1bf2f6184602bdfb73d10a155"
PAM_TACPLUS_TARBALL="${LINUX_DIR}/pam_tacplus-1.7.0.tar.gz"
LINUX_BUILDS_DIR="${LINUX_DIR}/builds"

# Stable UID for a user across every enrolled host. Allocated once, never
# reused, kept in $LINUX_UID_FILE as "name:uid" lines.
linux_uid_for() {
    local username="$1" uid
    touch "$LINUX_UID_FILE"
    uid=$(awk -F: -v u="$username" '$1 == u { print $2; exit }' "$LINUX_UID_FILE")
    if [[ -z "$uid" ]]; then
        uid=$(awk -F: -v base="$LINUX_UID_BASE" 'BEGIN { m = base - 1 } $2 > m { m = $2 } END { print m + 1 }' "$LINUX_UID_FILE")
        echo "${username}:${uid}" >> "$LINUX_UID_FILE"
    fi
    echo "$uid"
}

# "name:tier:uid" lines for every active user in a scope that can be a
# Linux account. Names useradd would reject are skipped with a warning.
# Disabled users (and the accounting sink) are left out by the model view,
# so a sync treats them like users removed from the scope: no new account,
# and an account tacctl created earlier is expired (which also stops
# SSH-key logins).
linux_scope_users() {
    local scope="$1" username privlvl tier rows
    rows=$(_model_view linux-users "$scope") || return 1
    while IFS='|' read -r username privlvl; do
        [[ -n "$username" && "$username" != "root" ]] || continue
        if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
            warn "Skipping '${username}': not a valid Linux account name (lowercase letters, digits, _ and - only)." >&2
            continue
        fi
        tier=$(tier_for_privlvl "$privlvl")
        if [[ "$tier" == "none" ]]; then
            warn "Skipping '${username}': its group has no priv-lvl." >&2
            continue
        fi
        echo "${username}:${tier}:$(linux_uid_for "$username")"
    done <<< "$rows"
}

# Number of users in a scope that would get a Linux account. Unlike
# linux_scope_users this assigns no UIDs, so read-only commands can use it.
linux_scope_user_count() {
    local scope="$1" username _privlvl n=0 rows
    rows=$(_model_view linux-users "$scope") || rows=""
    while IFS='|' read -r username _privlvl; do
        [[ "$username" =~ ^[a-z_][a-z0-9_-]{0,31}$ && "$username" != "root" ]] || continue
        n=$((n + 1))
    done <<< "$rows"
    echo "$n"
}

cmd_config_linux_build() {
    local tool
    for tool in git gnulib-tool autoreconf libtoolize make gcc; do
        if ! command -v "$tool" >/dev/null; then
            error "'${tool}' not found. Install the build tools first:"
            error "  apt install autoconf automake libtool gnulib libpam0g-dev build-essential git"
            return 1
        fi
    done
    local work
    work=$(mktemp -d)
    info "Fetching pam_tacplus ${PAM_TACPLUS_TAG}..."
    if ! git clone --quiet --depth 1 --branch "$PAM_TACPLUS_TAG" "$PAM_TACPLUS_REPO" "$work/src" 2>/dev/null; then
        rm -rf "$work"
        error "Could not clone ${PAM_TACPLUS_REPO}."
        return 1
    fi
    local got
    got=$(git -C "$work/src" rev-parse HEAD)
    if [[ "$got" != "$PAM_TACPLUS_COMMIT" ]]; then
        rm -rf "$work"
        error "Tag ${PAM_TACPLUS_TAG} resolved to ${got}, expected ${PAM_TACPLUS_COMMIT}. Refusing to build."
        return 1
    fi
    info "Preparing source tarball..."
    if ! (
        cd "$work/src"
        # Current gnulib no longer defines this macro; glibc provides
        # explicit_bzero, so the branch that used it is never taken.
        sed -i '/^  gl_PREREQ_EXPLICIT_BZERO$/d' configure.ac
        gnulib-tool --makefile-name=Makefile.gnulib --libtool --import \
            fcntl crypto/md5 array-list list xlist getrandom realloc-posix \
            explicit_bzero xalloc getopt-gnu
        autoreconf -f -i
        ./configure
        make dist
    ) >"$work/build.log" 2>&1; then
        tail -20 "$work/build.log" >&2
        rm -rf "$work"
        error "Preparing the pam_tacplus tarball failed."
        return 1
    fi
    mkdir -p "$LINUX_DIR"
    chmod 755 "$LINUX_DIR"
    install -m 0644 "$work/src/pam_tacplus-1.7.0.tar.gz" "$PAM_TACPLUS_TARBALL"
    rm -rf "$work"
    info "Wrote ${PAM_TACPLUS_TARBALL} (sha256 $(sha256sum "$PAM_TACPLUS_TARBALL" | awk '{print $1}'))."
}

# linux_write_install_script <scope> <server> <outfile> [accounts-only] [prebuilt-dir]
# Writes the per-scope client script to <outfile> (mode 0600). With a 4th
# argument the pam_tacplus tarball is left out: enough for --accounts-only.
# A 5th names a directory under $LINUX_BUILDS_DIR whose prebuilt module is
# embedded as well; the host uses it in preference to compiling.
linux_write_install_script() {
    local scope="$1" server="$2" output="$3" accounts_only="${4:-}" prebuilt="${5:-}"
    if [[ -z "$accounts_only" && ! -f "$PAM_TACPLUS_TARBALL" ]]; then
        error "pam_tacplus tarball not found. Run 'tacctl config linux build' first."
        return 1
    fi

    # pam_tacplus reads the secret as one whitespace-delimited PAM argument.
    local secret
    secret=$(model_scope "$scope" secret) || secret=""
    if [[ ! "$secret" =~ ^[A-Za-z0-9_.+/=-]+$ || "$secret" == REPLACE* ]]; then
        error "Scope '${scope}' has a secret that cannot be written on a PAM line (or a placeholder)."
        error "Regenerate it: tacctl scope secret ${scope} generate"
        return 1
    fi
    if [[ ! "$server" =~ ^[A-Za-z0-9.:-]+$ ]]; then
        error "Invalid server address '${server}'. Give a bare IPv4/IPv6 address or hostname (the port comes from 'tacctl config listen')."
        return 1
    fi

    # pam_tacplus talks to the TACACS+ backend's default listener
    # (listeners.tacacs.default in tacctl.yaml).
    local listen="" port _lname _lnet _laddr
    while read -r _lname _lnet _laddr; do
        [[ "$_lname" == "default" ]] && listen="$_laddr"
    done < <(backend_call tacacs listeners list)
    listen=${listen:-:49}
    port="${listen##*:}"

    LINUX_SCRIPT_USERS=$(linux_scope_users "$scope")
    LINUX_SCRIPT_PORT="$port"

    local tmp
    tmp=$(mktemp)
    {
        echo "#!/usr/bin/env bash"
        echo "# tacctl Linux client installer for scope '${scope}'. Generated $(date -u +%Y-%m-%dT%H:%M:%SZ)."
        echo "# CONTAINS THE SCOPE'S SHARED SECRET. Delete after use."
        echo "set -euo pipefail"
        echo "umask 077"
        printf 'TAC_SERVER=%q\n' "$server"
        printf 'TAC_PORT=%q\n' "$port"
        printf 'TAC_SECRET=%q\n' "$secret"
        printf 'TAC_SCOPE=%q\n' "$scope"
        if [[ -z "$accounts_only" ]]; then
            printf 'TARBALL_SHA256=%q\n' "$(sha256sum "$PAM_TACPLUS_TARBALL" | awk '{print $1}')"
            if [[ -n "$prebuilt" ]]; then
                printf 'PREBUILT_SHA256=%q\n' "$(sha256sum "$prebuilt/module.tar.gz" | awk '{print $1}')"
                printf 'PREBUILT_FOR=%q\n' "$(sed -n 's/^image=//p' "$prebuilt/info")"
            fi
        fi
        printf 'TAC_USERS=%q\n' "$LINUX_SCRIPT_USERS"
        cat "${LINUX_SRC_DIR}/client-install.sh"
        if [[ -z "$accounts_only" ]]; then
            echo "__TARBALL__"
            base64 "$PAM_TACPLUS_TARBALL"
            if [[ -n "$prebuilt" ]]; then
                echo "__PREBUILT__"
                base64 "$prebuilt/module.tar.gz"
            fi
        fi
    } > "$tmp"
    install -m 0600 "$tmp" "$output"
    rm -f "$tmp"
}

# --- Prebuilt modules ---
# podman runs as the user who invoked sudo (rootless), never as root unless
# tacctl itself was started by root.
_linux_podman() {
    if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        (cd / && sudo -u "$SUDO_USER" -H podman "$@")
    else
        podman "$@"
    fi
}

# linux_image_for_os <os-release text>: the container image that matches a
# host's userland, or nothing when tacctl knows none. Ubuntu derivatives
# (Mint, KDE neon, ...) name their base in UBUNTU_CODENAME.
linux_image_for_os() {
    local text="$1" id like major codename ubuntu
    id=$(sed -n 's/^ID=//p' <<< "$text" | head -1 | tr -d "\"'")
    codename=$(sed -n 's/^VERSION_CODENAME=//p' <<< "$text" | head -1 | tr -d "\"'")
    ubuntu=$(sed -n 's/^UBUNTU_CODENAME=//p' <<< "$text" | head -1 | tr -d "\"'")
    if [[ "$id" == "ubuntu" && -z "$ubuntu" ]]; then ubuntu="$codename"; fi
    if [[ "$ubuntu" =~ ^[a-z]+$ ]]; then
        echo "docker.io/library/ubuntu:${ubuntu}"
    elif [[ "$id" == "debian" && "$codename" =~ ^[a-z]+$ ]]; then
        echo "docker.io/library/debian:${codename}"
    else
        # RHEL and its rebuilds share an ABI per major release, so one
        # AlmaLinux image serves RHEL, CentOS Stream, Rocky, Alma and Oracle.
        like=$(sed -n 's/^ID_LIKE=//p' <<< "$text" | head -1 | tr -d "\"'")
        major=$(sed -n 's/^VERSION_ID=//p' <<< "$text" | head -1 | tr -d "\"'")
        major="${major%%.*}"
        if [[ " rhel centos almalinux rocky ol " == *" ${id} "* || " ${like} " == *" rhel "* ]] \
            && [[ "$major" =~ ^[0-9]+$ ]]; then
            echo "docker.io/library/almalinux:${major}"
        fi
    fi
}

# linux_host_platform <target> <port> <identity>: prints "<image>|<arch>"
# for the host (image empty when unknown). Fails if the host did not answer.
linux_host_platform() {
    local target="$1" port="$2" identity="$3" out arch
    # shellcheck disable=SC2016  # expanded by the probed shell
    local probe='cat /etc/os-release 2>/dev/null; echo; echo "TACCTL_ARCH=$(uname -m)"'
    if [[ "$target" == "local" ]]; then
        out=$(bash -c "$probe")
    else
        out=$(_host_ssh "$port" "$identity" -T "$target" "$probe" < /dev/null 2>/dev/null) || return 1
    fi
    arch=$(sed -n 's/^TACCTL_ARCH=//p' <<< "$out" | head -1)
    [[ "$arch" =~ ^[A-Za-z0-9_]+$ ]] || return 1
    echo "$(linux_image_for_os "$out")|${arch}"
}

# linux_prebuilt_for <image>: makes sure a pam_tacplus module built for
# <image> on this machine's architecture is cached, building it in a
# container on first use, and sets LINUX_PREBUILT to its directory. The
# tools image (base + compiler) is built with network access; the compile
# itself runs with none, reading the source on stdin and writing the two
# libraries to stdout.
linux_prebuilt_for() {
    local image="$1" key dir src_sha
    LINUX_PREBUILT=""
    if ! command -v podman >/dev/null; then
        warn "podman is not installed here (apt install podman uidmap)."
        return 1
    fi
    key="${image##*/}"
    key="${key//:/-}-$(uname -m)"
    dir="${LINUX_BUILDS_DIR}/${key}"
    src_sha=$(sha256sum "$PAM_TACPLUS_TARBALL" | awk '{print $1}')
    if [[ -s "$dir/module.tar.gz" && "$(sed -n 's/^source=//p' "$dir/info" 2>/dev/null)" == "$src_sha" ]]; then
        LINUX_PREBUILT="$dir"
        return 0
    fi

    info "Building pam_tacplus for ${image##*/} in a container (once per OS release; takes a minute or two)..."
    local work tools="localhost/tacctl-build:${key}"
    work=$(mktemp -d)
    chmod 755 "$work"
    mkdir "$work/ctx"
    chmod 755 "$work/ctx"
    # The Containerfile goes through a file, not stdin: podman reopens
    # /dev/stdin by path, which a pipe owned by root does not allow.
    local tools_cmd='apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends gcc make libc6-dev libpam0g-dev >/dev/null && rm -rf /var/lib/apt/lists/*'
    if [[ "$image" == */almalinux:* ]]; then
        tools_cmd='dnf install -y -q gcc make pam-devel tar gzip >/dev/null && dnf clean all >/dev/null'
    fi
    printf 'FROM %s\nRUN %s\n' "$image" "$tools_cmd" > "$work/ctx/Containerfile"
    chmod 644 "$work/ctx/Containerfile"
    if ! _linux_podman build -q -t "$tools" -f "$work/ctx/Containerfile" "$work/ctx" > "$work/log" 2>&1; then
        tail -5 "$work/log" >&2
        rm -rf "$work"
        warn "Could not prepare the build image for ${image}."
        return 1
    fi
    # shellcheck disable=SC2016  # runs inside the container
    local build='set -e; w=$(mktemp -d); cd "$w"; tar --no-same-owner -xzf -; cd pam_tacplus-*/
        ma=$(gcc -print-multiarch); if [ -n "$ma" ]; then lib=/usr/lib/$ma; else lib=/usr/lib64; fi
        ./configure --prefix=/usr --libdir="$lib" --enable-pamdir="$lib/security" >&2
        make >&2; make install DESTDIR="$w/stage" >&2
        mkdir "$w/out"; cp "$w/stage$lib/libtac.so.5.0.0" "$w/stage$lib/security/pam_tacplus.so" "$w/out/"
        tar -C "$w/out" -czf - libtac.so.5.0.0 pam_tacplus.so'
    if ! _linux_podman run --rm -i --network none --cap-drop all --security-opt no-new-privileges \
            "$tools" sh -c "$build" < "$PAM_TACPLUS_TARBALL" > "$work/module.tar.gz" 2> "$work/log" \
        || [[ "$(tar -tzf "$work/module.tar.gz" 2>/dev/null | sort | paste -sd' ')" != "libtac.so.5.0.0 pam_tacplus.so" ]]; then
        tail -20 "$work/log" >&2
        rm -rf "$work"
        warn "The container build of pam_tacplus for ${image} failed."
        return 1
    fi
    mkdir -p "$dir"
    chmod 755 "$LINUX_BUILDS_DIR" "$dir"
    install -m 0644 "$work/module.tar.gz" "$dir/module.tar.gz"
    {
        echo "image=${image}"
        echo "digest=$(_linux_podman image inspect --format '{{.Digest}}' "$image" 2>/dev/null || true)"
        echo "arch=$(uname -m)"
        echo "source=${src_sha}"
        echo "built=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    } > "$dir/info"
    rm -rf "$work"
    LINUX_PREBUILT="$dir"
    info "Cached in ${dir}."
}

cmd_config_linux_builds() {
    local sub="${1:-list}" dir
    case "$sub" in
        list)
            echo ""
            echo -e "${BOLD}Prebuilt pam_tacplus modules${NC} (${LINUX_BUILDS_DIR})"
            echo "--------------------------------------------"
            local any=0
            for dir in "$LINUX_BUILDS_DIR"/*/; do
                [[ -f "${dir}info" ]] || continue
                any=1
                printf "  %-28s %-8s built %s\n      base image %s\n" \
                    "$(sed -n 's/^image=//p' "${dir}info" | sed 's|.*/||')" \
                    "$(sed -n 's/^arch=//p' "${dir}info")" \
                    "$(sed -n 's/^built=//p' "${dir}info")" \
                    "$(sed -n 's/^digest=//p' "${dir}info")"
            done
            if [[ "$any" == "0" ]]; then
                echo "  None yet. 'tacctl host enroll' builds one the first time it meets an OS release."
            fi
            echo ""
            ;;
        clear)
            rm -rf "$LINUX_BUILDS_DIR"
            info "Prebuilt modules removed; the next enroll of each OS release rebuilds."
            ;;
        *)
            error "Usage: tacctl config linux builds [list|clear]"
            return 1
            ;;
    esac
}

cmd_config_linux_script() {
    local scope="" server="" output=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scope)  scope="${2:-}";  shift 2 || true ;;
            --server) server="${2:-}"; shift 2 || true ;;
            --output|-o) output="${2:-}"; shift 2 || true ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl config linux script [--scope <name>] [--server <address>] [--output <file>]"
                return 1
                ;;
        esac
    done
    if [[ -z "$scope" ]]; then
        scope=$(read_default_scope)
        [[ -n "$scope" ]] || { error "No default scope set and no --scope provided."; return 1; }
    elif ! _scope_require "$scope"; then
        return 1
    fi
    if [[ -z "$server" ]]; then
        server=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
        [[ -n "$server" ]] || { error "Could not detect this server's address. Pass --server <address>."; return 1; }
    fi

    output="${output:-tacctl-linux-${scope}.sh}"
    linux_write_install_script "$scope" "$server" "$output" || return 1
    local users="$LINUX_SCRIPT_USERS" port="$LINUX_SCRIPT_PORT"
    if [[ -z "$users" ]]; then
        warn "No users in scope '${scope}' can become Linux accounts; the script installs TACACS+ with no users."
    fi
    # Under sudo the file would otherwise be root's; hand it to the caller.
    if [[ -n "${SUDO_UID:-}" ]]; then
        chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$output" 2>/dev/null || true
    fi

    info "Wrote ${output} (mode 0600; contains the shared secret for scope '${scope}')."
    echo ""
    echo "  Server:  ${server} port ${port}"
    echo "  Users:   $(awk -F: 'NF { printf "%s(%s) ", $1, $2 }' <<< "$users")"
    echo ""
    echo "  The target host's address must be inside scope '${scope}':"
    echo "    tacctl scope lookup <host-ip>"
    echo "  On the target host, as root, from a session you keep open:"
    echo "    bash ${output##*/}                   # install"
    echo "    bash ${output##*/} --accounts-only   # later: sync users only"
    echo "  Then delete the script. 'tacctl host enroll' does all of this over SSH."
    echo ""
}

cmd_config_linux_remove_script() {
    local output=""
    case "${1:-}" in
        --output|-o) output="${2:-}" ;;
        "") ;;
        *) error "Usage: tacctl config linux remove-script [--output <file>]"; return 1 ;;
    esac
    output="${output:-tacctl-linux-remove.sh}"
    install -m 0644 "${LINUX_SRC_DIR}/client-remove.sh" "$output"
    if [[ -n "${SUDO_UID:-}" ]]; then
        chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$output" 2>/dev/null || true
    fi
    info "Wrote ${output} (no secrets). Run it as root on the host to remove TACACS+ authentication."
    info "Local accounts and home directories are left in place."
}

# 'config linux uid': show or change the number a user gets as UID and
# primary GID on every host. Changing it does not renumber accounts that
# already exist on enrolled hosts; the next sync reports them.
cmd_config_linux_uid() {
    local username="${1:-}" uid="${2:-}"
    touch "$LINUX_UID_FILE"
    if [[ -z "$username" ]]; then
        echo ""
        echo -e "${BOLD}Assigned Linux UIDs${NC} (same number is the primary GID)"
        echo "--------------------------------------------"
        if [[ -s "$LINUX_UID_FILE" ]]; then
            sort -t: -k2 -n "$LINUX_UID_FILE" | awk -F: '{ printf "  %-24s %s\n", $1, $2 }'
        else
            echo "  None yet. A UID is assigned the first time a user is sent to a host."
        fi
        echo ""
        echo "  Change one: tacctl config linux uid <username> <uid>"
        echo ""
        return 0
    fi
    validate_username "$username"
    if [[ -z "$uid" ]]; then
        uid=$(awk -F: -v u="$username" '$1 == u { print $2; exit }' "$LINUX_UID_FILE")
        if [[ -z "$uid" ]]; then
            error "No UID assigned to '${username}' yet."
            return 1
        fi
        echo "$uid"
        return 0
    fi
    if ! model_user_exists "$username"; then
        error "User '${username}' does not exist."
        return 1
    fi
    if [[ ! "$uid" =~ ^[0-9]{4,9}$ ]] || (( uid < 1000 || uid == 65534 )); then
        error "UID must be a number from 1000 up (not 65534)."
        return 1
    fi
    local holder
    holder=$(awk -F: -v id="$uid" '$2 == id { print $1; exit }' "$LINUX_UID_FILE")
    if [[ -n "$holder" && "$holder" != "$username" ]]; then
        error "UID ${uid} is already assigned to '${holder}'."
        return 1
    fi
    local tmp
    tmp=$(mktemp)
    awk -F: -v u="$username" '$1 != u' "$LINUX_UID_FILE" > "$tmp"
    echo "${username}:${uid}" >> "$tmp"
    install -m 0600 "$tmp" "$LINUX_UID_FILE"
    rm -f "$tmp"
    info "'${username}' is now assigned UID/GID ${uid}."
    warn "Hosts that already have the account keep its old number until it is renumbered there:"
    echo "    usermod -u ${uid} ${username} && groupmod -g ${uid} ${username}"
    echo "    find / -xdev \\( -uid <old> -o -gid <old> \\) -exec chown -h ${username}:${username} {} +"
    echo "  'tacctl host sync' lists the hosts where the number still differs."
}

cmd_config_linux() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        build)         cmd_config_linux_build ;;
        script)        cmd_config_linux_script "$@" ;;
        remove-script) cmd_config_linux_remove_script "$@" ;;
        uid)           cmd_config_linux_uid "$@" ;;
        builds)        cmd_config_linux_builds "$@" ;;
        *)
            echo ""
            echo -e "${BOLD}Linux host TACACS+ login${NC}"
            echo ""
            echo "Usage: tacctl config linux <subcommand>"
            echo ""
            echo "  build                                   Fetch and prepare the pinned pam_tacplus source (once, and after upgrades)"
            echo "  script [--scope <name>] [--server <address>] [--output <file>]"
            echo "                                          Write the install script for hosts in a scope (contains the secret)"
            echo "  remove-script [--output <file>]         Write the removal script (no secrets; accounts are left in place)"
            echo "  uid [<username> [<uid>]]                Show or change the UID/GID a user gets on every host"
            echo "  builds [list|clear]                     Show or drop the modules 'host enroll' built in containers"
            echo ""
            [[ -z "$sub" ]] && return 0
            return 1
            ;;
    esac
}

# =====================================================================
#  HOST COMMANDS (enroll / sync / unenroll Linux hosts)
# =====================================================================
#
# 'tacctl host' pushes the 'config linux' scripts to a host and runs them
# there, and keeps a registry of enrolled hosts so 'host sync' knows where
# to push account changes. One line per host in $LINUX_HOSTS_FILE:
#   name|target|port|scope|server|identity
# target is [user@]host for ssh, or 'local' for this machine.
#
# ssh runs as the user who invoked sudo, so their keys and known_hosts are
# used. The remote login must be root or able to sudo.
LINUX_HOSTS_FILE="${TACCTL_STATE_DIR}/linux-hosts"

host_record() { # <name> -> registry line, or nothing
    [[ -f "$LINUX_HOSTS_FILE" ]] || return 0
    awk -F'|' -v n="$1" '$1 == n { print; exit }' "$LINUX_HOSTS_FILE"
}

host_forget() {
    [[ -f "$LINUX_HOSTS_FILE" ]] || return 0
    local tmp
    tmp=$(mktemp)
    awk -F'|' -v n="$1" '$1 != n' "$LINUX_HOSTS_FILE" > "$tmp"
    install -m 0600 "$tmp" "$LINUX_HOSTS_FILE"
    rm -f "$tmp"
}

host_remember() { # <name> <target> <port> <scope> <server> <identity>
    host_forget "$1"
    local IFS='|'
    echo "$*" >> "$LINUX_HOSTS_FILE"
    chmod 600 "$LINUX_HOSTS_FILE"
}

_host_ssh() { # <port> <identity> <ssh args...>
    local port="$1" identity="$2"
    shift 2
    local -a cmd=()
    if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
        cmd=(sudo -u "$SUDO_USER" -H)
        [[ -n "${SSH_AUTH_SOCK:-}" ]] && cmd+=(env "SSH_AUTH_SOCK=${SSH_AUTH_SOCK}")
    fi
    cmd+=(ssh -o ConnectTimeout=10)
    # One connection per host for the whole command: the probe, the copy
    # and the run share it, so a login that needs a password or a key
    # passphrase is asked for it once instead of once per step. The socket
    # sits in the ssh user's own ~/.ssh; host_run_script closes it, and it
    # goes away by itself a minute after the last use.
    cmd+=(-o ControlMaster=auto -o "ControlPath=~/.ssh/tacctl-%C" -o ControlPersist=60)
    # With no terminal nobody can answer a password or host-key prompt:
    # fail instead of waiting on one.
    if ! { : > /dev/tty; } 2>/dev/null; then cmd+=(-o BatchMode=yes); fi
    [[ -n "$port" ]] && cmd+=(-p "$port")
    [[ -n "$identity" ]] && cmd+=(-i "$identity")
    "${cmd[@]}" "$@"
}

# host_run_script <target> <port> <identity> <script> [script args...]
# Copies <script> to the host and runs it as root there; for target
# 'local' runs it here. The remote copy is deleted afterwards (the install
# script holds the scope secret).
host_run_script() {
    local target="$1" port="$2" identity="$3" script="$4"
    shift 4
    if [[ "$target" == "local" ]]; then
        bash "$script" "$@"
        return
    fi
    local remote
    # shellcheck disable=SC2016  # expanded by the remote shell
    remote=$(_host_ssh "$port" "$identity" "$target" \
        'umask 077; f=$(mktemp /tmp/tacctl.XXXXXXXX) && cat > "$f" && echo "$f"' < "$script") || {
        error "Could not copy the script to ${target} (ssh failed)."
        return 1
    }
    if [[ ! "$remote" =~ ^/tmp/tacctl\.[A-Za-z0-9]+$ ]]; then
        error "Unexpected reply from ${target} while copying the script."
        return 1
    fi
    # A terminal lets the remote sudo prompt for a password (the prompt
    # names the host, since 'host sync --all' asks once per host). Without
    # one only passwordless sudo or a root login can work, so say so
    # instead of failing on sudo's own message. The copy holds the scope
    # secret: it is removed however the remote shell ends.
    local tty_flag="-T" run
    if [[ -t 0 ]]; then
        tty_flag="-t"
        run="sudo -p '[sudo] password for %u on %H: ' bash ${remote} $*"
    else
        run="if sudo -n true 2>/dev/null; then sudo -n bash ${remote} $*; else echo '[ERROR] sudo on this host needs a password and there is no terminal to ask on. Run tacctl host from a terminal, allow passwordless sudo for this login, or log in as root.' >&2; false; fi"
    fi
    local remote_cmd="trap 'rm -f ${remote}' EXIT; trap 'exit 130' HUP INT TERM; if [ \"\$(id -u)\" = 0 ]; then bash ${remote} $*; else ${run}; fi"
    local rc=0
    _host_ssh "$port" "$identity" "$tty_flag" "$target" "$remote_cmd" || rc=$?
    _host_ssh "$port" "$identity" -O exit "$target" > /dev/null 2>&1 || true
    return "$rc"
}

# Address the host should use to reach this server: the source address of
# our route to it.
host_server_address_for() {
    local dest="$1" src
    src=$(ip -4 route get "$dest" 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    echo "$src"
}

cmd_host_enroll() {
    local target="" scope="" server="" name="" port="" identity="" is_local=0 build_on_host=0
    local -a script_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local)    is_local=1; shift ;;
            --build-on-host) build_on_host=1; shift ;;
            --allow-uid-mismatch) script_args+=(--allow-uid-mismatch); shift ;;
            --adopt)
                if [[ ! "${2:-}" =~ ^[a-z_][a-z0-9_-]*(,[a-z_][a-z0-9_-]*)*$ ]]; then
                    error "--adopt needs a comma-separated list of account names."
                    return 1
                fi
                script_args+=(--adopt "$2"); shift 2
                ;;
            --scope)    scope="${2:-}";    shift 2 || true ;;
            --server)   server="${2:-}";   shift 2 || true ;;
            --name)     name="${2:-}";     shift 2 || true ;;
            --port)     port="${2:-}";     shift 2 || true ;;
            --identity) identity="${2:-}"; shift 2 || true ;;
            -*) error "Unknown option: '$1'"; cmd_host_usage; return 1 ;;
            *)
                [[ -z "$target" ]] || { error "Only one host per enroll."; return 1; }
                target="$1"; shift
                ;;
        esac
    done

    local host_part host_ip
    if [[ "$is_local" == "1" ]]; then
        [[ -z "$target" ]] || { error "--local takes no host argument."; return 1; }
        target="local"
        host_ip="127.0.0.1"
        name="${name:-$(hostname -s)}"
        server="${server:-127.0.0.1}"
    else
        if [[ ! "$target" =~ ^([a-z_][a-z0-9_-]*@)?[A-Za-z0-9][A-Za-z0-9.:-]*$ ]]; then
            error "Usage: tacctl host enroll <[user@]host> | --local  [options]"
            return 1
        fi
        host_part="${target#*@}"
        host_ip=$(getent ahostsv4 "$host_part" 2>/dev/null | awk '{print $1; exit}')
        [[ -n "$host_ip" ]] || { error "Could not resolve '${host_part}' to an IPv4 address."; return 1; }
        if [[ -z "$name" ]]; then
            # A bare IP has no hostname to borrow: 10.1.2.3 -> h10-1-2-3.
            if [[ "$host_part" =~ ^[0-9.]+$ ]]; then name="h${host_part//./-}"; else name="${host_part%%.*}"; fi
        fi
        # Re-enrolling a registered host keeps the server address it has.
        if [[ -z "$server" && "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
            server=$(host_record "$name" | cut -d'|' -f5)
        fi
        if [[ -z "$server" ]]; then
            server=$(host_server_address_for "$host_ip")
            [[ -n "$server" ]] || { error "Could not work out which address ${host_part} should use for this server. Pass --server."; return 1; }
        fi
    fi
    if [[ ! "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,25}$ ]]; then
        error "Invalid host name '${name}'. Pass --name <letters, digits, _ or -, starting with a letter, max 26>."
        return 1
    fi
    if [[ -n "$port" && ! "$port" =~ ^[0-9]{1,5}$ ]]; then
        error "Invalid --port '${port}'."
        return 1
    fi
    if [[ -n "$identity" && ! -f "$identity" ]]; then
        error "Identity file '${identity}' not found."
        return 1
    fi
    if [[ ! -f "$PAM_TACPLUS_TARBALL" ]]; then
        error "pam_tacplus tarball not found. Run 'tacctl config linux build' first."
        return 1
    fi

    # Each host gets its own scope (its address as a /32, its own secret)
    # unless told to share one, so a secret read off one host is useless
    # from any other.
    if [[ -z "$scope" ]]; then
        scope="linux-${name}"
        if model_scope_exists "$scope"; then
            info "Using existing scope '${scope}'."
        else
            info "Creating scope '${scope}' for ${host_ip}/32..."
            cmd_scope_add "$scope" --prefixes "${host_ip}/32" --secret generate >/dev/null
        fi
    elif ! _scope_require "$scope"; then
        return 1
    fi

    # Build the module here for the host's OS release when we can, so the
    # host needs no compiler. Anything short of that falls back to
    # compiling on the host from the embedded source.
    local prebuilt="" platform image arch
    if [[ "$build_on_host" == "1" ]]; then
        info "pam_tacplus will be compiled on the host (--build-on-host)."
    elif platform=$(linux_host_platform "$target" "$port" "$identity"); then
        image="${platform%%|*}"
        arch="${platform##*|}"
        if [[ -z "$image" ]]; then
            info "No container image is known for this host's OS; pam_tacplus will be compiled on the host."
        elif [[ "$arch" != "$(uname -m)" ]]; then
            info "The host is ${arch} and this server is $(uname -m); pam_tacplus will be compiled on the host."
        elif linux_prebuilt_for "$image"; then
            prebuilt="$LINUX_PREBUILT"
        else
            warn "pam_tacplus will be compiled on the host instead."
        fi
    fi

    local script
    script=$(mktemp)
    linux_write_install_script "$scope" "$server" "$script" "" "$prebuilt" || { rm -f "$script"; return 1; }
    info "Enrolling ${name} (${target}) in scope '${scope}', server ${server}..."
    if ! host_run_script "$target" "$port" "$identity" "$script" "${script_args[@]}"; then
        rm -f "$script"
        error "Enrollment of ${name} failed; the host was not registered."
        return 1
    fi
    rm -f "$script"
    host_remember "$name" "$target" "$port" "$scope" "$server" "$identity"
    logger -t tacctl -p auth.info "host enroll name=${name} target=${target} scope=${scope} by=${SUDO_USER:-root}" 2>/dev/null || true
    info "Host '${name}' enrolled."
    if [[ -z "$LINUX_SCRIPT_USERS" ]]; then
        echo ""
        echo "  No users are in scope '${scope}' yet. To give someone a login on this host:"
        echo "    tacctl user scope <username> add ${scope}"
        echo "    tacctl host sync ${name}"
        echo ""
    fi
}

cmd_host_sync() {
    local which=""
    local -a script_args=(--accounts-only)
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --allow-uid-mismatch) script_args+=(--allow-uid-mismatch); shift ;;
            --adopt)
                if [[ ! "${2:-}" =~ ^[a-z_][a-z0-9_-]*(,[a-z_][a-z0-9_-]*)*$ ]]; then
                    error "--adopt needs a comma-separated list of account names."
                    return 1
                fi
                script_args+=(--adopt "$2"); shift 2
                ;;
            --all) which="--all"; shift ;;
            -*) error "Unknown option: '$1'"; return 1 ;;
            *) which="$1"; shift ;;
        esac
    done
    if [[ -z "$which" ]]; then
        error "Usage: tacctl host sync <name> | --all  [--allow-uid-mismatch] [--adopt <name>[,<name>...]]"
        return 1
    fi
    local -a names=()
    if [[ "$which" == "--all" ]]; then
        [[ -f "$LINUX_HOSTS_FILE" ]] && mapfile -t names < <(cut -d'|' -f1 "$LINUX_HOSTS_FILE")
        if [[ ${#names[@]} -eq 0 ]]; then
            info "No hosts enrolled."
            return 0
        fi
    else
        [[ -n "$(host_record "$which")" ]] || { error "No enrolled host named '${which}'. See 'tacctl host list'."; return 1; }
        names=("$which")
    fi

    local name target port scope server identity script failed=0
    for name in "${names[@]}"; do
        IFS='|' read -r _ target port scope server identity <<< "$(host_record "$name")"
        if ! model_scope_exists "$scope"; then
            error "${name}: scope '${scope}' no longer exists; skipped."
            failed=1
            continue
        fi
        script=$(mktemp)
        if linux_write_install_script "$scope" "$server" "$script" accounts-only \
            && host_run_script "$target" "$port" "$identity" "$script" "${script_args[@]}"; then
            info "${name}: synced ($(awk -F: 'NF { n++ } END { print n + 0 }' <<< "$LINUX_SCRIPT_USERS") users)."
        else
            error "${name}: sync failed (see the host's output above; nothing was changed there if it reported a conflict)."
            failed=1
        fi
        rm -f "$script"
    done
    return "$failed"
}

cmd_host_unenroll() {
    local name="" force=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force=1; shift ;;
            -*) error "Unknown option: '$1'"; return 1 ;;
            *) name="$1"; shift ;;
        esac
    done
    if [[ -z "$name" ]]; then
        error "Usage: tacctl host unenroll <name> [--force]"
        return 1
    fi
    local record target port scope identity
    record=$(host_record "$name")
    [[ -n "$record" ]] || { error "No enrolled host named '${name}'. See 'tacctl host list'."; return 1; }
    IFS='|' read -r _ target port scope _ identity <<< "$record"

    info "Removing TACACS+ authentication from ${name} (${target})..."
    if ! host_run_script "$target" "$port" "$identity" "${LINUX_SRC_DIR}/client-remove.sh"; then
        if [[ "$force" != "1" ]]; then
            error "Removal on ${name} failed; it is still registered. Fix the cause, or pass --force to forget the host anyway."
            return 1
        fi
        warn "Removal on ${name} failed; forgetting the host anyway (--force)."
    fi
    host_forget "$name"
    logger -t tacctl -p auth.info "host unenroll name=${name} target=${target} by=${SUDO_USER:-root}" 2>/dev/null || true
    info "Host '${name}' unenrolled. Local accounts and home directories were left in place."
    if [[ -z "$(awk -F'|' -v s="$scope" '$4 == s' "$LINUX_HOSTS_FILE" 2>/dev/null)" ]]; then
        echo ""
        echo "  No enrolled host uses scope '${scope}' any more. To stop its secret being accepted:"
        echo "    tacctl scope remove ${scope}"
        echo ""
    fi
}

cmd_host_list() {
    echo ""
    echo -e "${BOLD}Enrolled Linux hosts${NC}"
    echo "--------------------------------------------"
    if [[ ! -s "$LINUX_HOSTS_FILE" ]]; then
        echo "  None. Enroll one with: tacctl host enroll <[user@]host>"
        echo ""
        return
    fi
    printf "  ${BOLD}%-20s %-28s %-20s %-16s %s${NC}\n" "NAME" "TARGET" "SCOPE" "SERVER" "USERS"
    local name target port scope server _identity
    while IFS='|' read -r name target port scope server _identity; do
        [[ -n "$name" ]] || continue
        printf "  %-20s %-28s %-20s %-16s %s\n" "$name" "${target}${port:+:$port}" "$scope" "$server" \
            "$(linux_scope_user_count "$scope")"
    done < "$LINUX_HOSTS_FILE"
    echo ""
}

cmd_host_usage() {
    echo ""
    echo -e "${BOLD}Host Commands${NC} (TACACS+ login for Linux hosts)"
    echo ""
    echo "Usage: tacctl host <subcommand> [arguments]"
    echo ""
    echo "  list                                 Show enrolled hosts"
    echo "  enroll <[user@]host> [options]       Install TACACS+ login on a host over SSH and register it"
    echo "  enroll --local [options]             Same, for this machine"
    echo "      --scope <name>                   Use an existing scope (default: create linux-<name> for the host's /32)"
    echo "      --server <address>               Address the host should use for this server (default: detected)"
    echo "      --name <name>                    Registry name (default: short hostname)"
    echo "      --port <n>, --identity <file>    SSH port and key"
    echo "      --build-on-host                  Compile pam_tacplus on the host instead of in a container here"
    echo "  sync <name> | --all                  Push account adds, removals and tier changes"
    echo "      --allow-uid-mismatch             (enroll and sync) accept a UID/GID conflict on the host instead of stopping"
    echo "      --adopt <name>[,<name>...]       (enroll and sync) take over accounts that already exist on the host"
    echo "  unenroll <name> [--force]            Remove TACACS+ login from the host (accounts and homes are kept)"
    echo ""
    echo "ssh runs as the user who invoked sudo; the remote login must be root or able to sudo."
    echo ""
}

cmd_host() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        list)     cmd_host_list ;;
        enroll)   cmd_host_enroll "$@" ;;
        sync)     cmd_host_sync "$@" ;;
        unenroll) cmd_host_unenroll "$@" ;;
        "")       cmd_host_usage ;;
        *)        error "Unknown subcommand: '${sub}'"; cmd_host_usage; return 1 ;;
    esac
}

