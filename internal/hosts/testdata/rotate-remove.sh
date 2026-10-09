#!/usr/bin/env bash
# tacctl: remove a provisioning account (tacctl host provisioner ... rotate).
# Deleted after use.
set -euo pipefail
umask 077
ACCOUNT=admin
REMOVE_HOME=0
SUDOERS_ONLY=0
FORBIDDEN=80000-89999\ 20000-29999
SUDOERS_FILE=/etc/sudoers.d/tacctl-provisioner
STATE_DIR=/var/lib/tacctl-provisioner

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# ROTATE_TEST is fixed here, never read from the environment (this script runs
# as root, and the environment of an ssh session is not trusted): 0 on every
# host. The test suite turns the knobs below on by rewriting this one line in
# the copy of the script it runs; the production script never has a 1.
ROTATE_TEST=0
# The test suite points the fixed locations at a scratch directory.
LOGIN_DEFS="/etc/login.defs"
HOME_ROOT="/home"
HOME_OWNER=""
PASSWD_FILE="/etc/passwd"
ROOT_UID=0
SUDOERS_SCAN="/etc/sudoers /etc/sudoers.d/*"
USE_FLOCK=1
if [[ "$ROTATE_TEST" == "1" ]]; then
    LOGIN_DEFS="${TACCTL_ROTATE_LOGIN_DEFS:-/etc/login.defs}"
    HOME_ROOT="${TACCTL_ROTATE_HOME_ROOT:-/home}"
    HOME_OWNER="${TACCTL_ROTATE_HOME_OWNER:-}"
    PASSWD_FILE="${TACCTL_ROTATE_PASSWD:-/etc/passwd}"
    ROOT_UID="${TACCTL_ROTATE_ROOT_UID:-0}"
    STATE_DIR="${TACCTL_ROTATE_STATE:-$STATE_DIR}"
    SUDOERS_FILE="${TACCTL_ROTATE_SUDOERS:-$SUDOERS_FILE}"
    SUDOERS_SCAN="${TACCTL_ROTATE_SUDOERS_SCAN:-$SUDOERS_FILE}"
    if [[ "${TACCTL_ROTATE_NOFLOCK:-}" == "1" ]]; then USE_FLOCK=0; fi
elif [[ "$(id -u)" != "0" ]]; then
    die "This script must run as root. Nothing was changed."
fi
if ! command -v flock >/dev/null 2>&1; then USE_FLOCK=0; fi
trap 'exit 130' HUP INT TERM
trap 'exit 141' PIPE

# uid_forbidden <uid>: the number is in tacctl's range or one it used before.
uid_forbidden() {
    local r
    for r in $FORBIDDEN; do
        if (( $1 >= ${r%-*} && $1 <= ${r#*-} )); then return 0; fi
    done
    return 1
}

# locked <command...>: the command, with the lock on the sudoers file held
# (flock, or a lock directory where flock is missing), so that two scripts
# at once do not lose each other's line: the file is read, changed and
# renamed in one go.
LOCK_FILE="$(dirname "$SUDOERS_FILE")/.tacctl-provisioner.lock"
locked() {
    local rc=0 d="${LOCK_FILE}.d" i pid
    mkdir -p "$(dirname "$SUDOERS_FILE")" || return 1
    if [[ "$USE_FLOCK" == "1" ]]; then
        (
            flock -w 120 9 || { echo "[ERROR] Could not take the lock ${LOCK_FILE}: another script is changing the sudoers file." >&2; exit 98; }
            "$@"
        ) 9>"$LOCK_FILE" || rc=$?
        return "$rc"
    fi
    for ((i = 0; i < 240; i++)); do
        if mkdir "$d" 2>/dev/null; then echo "$$" > "$d/pid"; break; fi
        pid=$(cat "$d/pid" 2>/dev/null || true)
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then rm -rf "$d"; continue; fi
        sleep 0.5
    done
    if [[ "$(cat "$d/pid" 2>/dev/null || true)" != "$$" ]]; then
        echo "[ERROR] Could not take the lock ${d}: another script is changing the sudoers file." >&2
        return 1
    fi
    "$@" || rc=$?
    rm -rf "$d"
    return "$rc"
}

# sudoers_lines: the lines of the other accounts in SUDOERS_FILE.
sudoers_lines() {
    [[ -f "$SUDOERS_FILE" ]] || return 0
    { grep -vE '^[[:space:]]*(#|$)' "$SUDOERS_FILE" | grep -v "^${ACCOUNT}[[:space:]]"; } || true
}

# sudoers_own_line: the account's line in SUDOERS_FILE ("" when none).
sudoers_own_line() {
    [[ -f "$SUDOERS_FILE" ]] || return 0
    { grep -E "^${ACCOUNT}[[:space:]]" "$SUDOERS_FILE" | head -n 1; } || true
}

# sudoers_write_unlocked <line>: SUDOERS_FILE with the other accounts' lines
# and <line> (when not empty), checked by visudo before it replaces the file.
sudoers_write_unlocked() {
    local tmp dir
    dir=$(dirname "$SUDOERS_FILE")
    tmp=$(mktemp "$dir/.tacctl-provisioner.XXXXXX") || return 1
    {
        echo "# Managed by tacctl (tacctl host provisioner): provisioning accounts, one line each."
        sudoers_lines
        if [[ -n "$1" ]]; then echo "$1"; fi
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 0440 "$tmp" || { rm -f "$tmp"; return 1; }
    if ! visudo -cf "$tmp" >/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    if [[ "$ROTATE_TEST" != "1" ]]; then chown root:root "$tmp" || { rm -f "$tmp"; return 1; }; fi
    mv -f "$tmp" "$SUDOERS_FILE" || { rm -f "$tmp"; return 1; }
}

# sudoers_drop_unlocked: the account's line goes; the file too when it holds no other.
sudoers_drop_unlocked() {
    [[ -f "$SUDOERS_FILE" ]] || return 0
    if [[ -z "$(sudoers_lines)" ]]; then
        rm -f "$SUDOERS_FILE"
    else
        sudoers_write_unlocked ""
    fi
}

sudoers_write() { locked sudoers_write_unlocked "$1"; }
sudoers_drop()  { locked sudoers_drop_unlocked; }

# Root's record of the accounts this script made: STATE_DIR/<account>, in a
# directory of root's alone, with the lines account=, uid= and ssh_dir=
# (1: ~/.ssh was made by this script). It is what an adoption trusts.
# Nothing in the account's own reach (its comment field, its home) is
# trusted, and the file is read as text, never run.

# state_get <key>: the value in the account's record ("" when none).
state_get() { sed -n "s/^$1=//p" "$STATE_DIR/$ACCOUNT" 2>/dev/null | head -n 1; }

# state_valid <uid>: the record is root's, in root's directory, and names
# this account and this UID.
state_valid() {
    local f="$STATE_DIR/$ACCOUNT"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" && -f "$f" && ! -L "$f" ]] || return 1
    [[ "$(stat -c %u "$STATE_DIR")" == "$ROOT_UID" && "$(stat -c %u "$f")" == "$ROOT_UID" ]] || return 1
    (( ( 8#$(stat -c %a "$STATE_DIR") & 077 ) == 0 && ( 8#$(stat -c %a "$f") & 022 ) == 0 )) || return 1
    [[ "$(state_get account)" == "$ACCOUNT" && "$(state_get uid)" == "$1" ]]
}

# state_write <uid> <ssh_dir>: the record, through a temporary file.
state_write() {
    local tmp
    if [[ -L "$STATE_DIR" || ( -e "$STATE_DIR" && ! -d "$STATE_DIR" ) ]]; then return 1; fi
    if [[ ! -d "$STATE_DIR" ]]; then mkdir -m 0700 "$STATE_DIR" 2>/dev/null || [[ -d "$STATE_DIR" ]] || return 1; fi
    [[ "$(stat -c %u "$STATE_DIR")" == "$ROOT_UID" ]] || return 1
    chmod 0700 "$STATE_DIR" || return 1
    tmp=$(mktemp "$STATE_DIR/.record.XXXXXX") || return 1
    { printf 'account=%s\nuid=%s\nssh_dir=%s\n' "$ACCOUNT" "$1" "$2" > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$STATE_DIR/$ACCOUNT"; } || { rm -f "$tmp"; return 1; }
}

# state_forget: the record goes (and the directory with the last one).
state_forget() {
    rm -f "$STATE_DIR/$ACCOUNT"
    rmdir "$STATE_DIR" 2>/dev/null || true
}

for c in userdel getent visudo stat; do
    command -v "$c" >/dev/null 2>&1 || die "'$c' is not installed on this host."
done

# home_refusal <name> <uid> <home>: why the home directory must stay ("" when
# it may go): it must be a real directory directly under /home (no symbolic
# link on the way), owned by the account, and no other account's home.
home_refusal() {
    local name="$1" uid="$2" home="$3" other
    if [[ "$home" != "${HOME_ROOT}/"* || "${home#"${HOME_ROOT}"/}" == */* || "${home#"${HOME_ROOT}"/}" == "" || "${home#"${HOME_ROOT}"/}" == .* ]]; then
        echo "not a directory directly under ${HOME_ROOT}"; return 0
    fi
    if [[ -L "$HOME_ROOT" ]]; then echo "${HOME_ROOT} is a symbolic link"; return 0; fi
    if [[ -L "$home" ]]; then echo "it is a symbolic link"; return 0; fi
    if [[ ! -d "$home" ]]; then echo "not a directory"; return 0; fi
    other=$(getent passwd | awk -F: -v n="$name" -v h="$home" '$1 != n && ($6 == h || index($6, h "/") == 1) { print $1; exit }')
    if [[ -n "$other" ]]; then echo "also the home of '${other}'"; return 0; fi
    if [[ "$(stat -c %u "$home")" != "${HOME_OWNER:-$uid}" ]]; then echo "owned by UID $(stat -c %u "$home"), not ${uid}"; return 0; fi
    return 0
}

# Kept homes of removed accounts are moved here, out of reach of a local
# account that is later given the same UID: root's alone, the tree owned by
# root.
REMOVED_DIR="${HOME_ROOT}/.tacctl-removed"

# keep_home <name> <home>: the home moves to REMOVED_DIR/<name>-<YYYYmmdd-HHMMSS>,
# owned by root:root (links changed, never followed), its top 0700. It stays
# where it is (and says why) when REMOVED_DIR is not a real directory of
# root's, the home is on another file system than ${HOME_ROOT}, or the name
# is taken.
keep_home() {
    local name="$1" home="$2" dest
    dest="${REMOVED_DIR}/${name}-$(date +%Y%m%d-%H%M%S)"
    if [[ -L "$REMOVED_DIR" || ( -e "$REMOVED_DIR" && ! -d "$REMOVED_DIR" ) ]]; then
        warn "home kept in place: ${home} (${REMOVED_DIR} is not a real directory); move it out of reach of new accounts by hand."
        return 0
    fi
    if [[ "$(stat -c %d "$home")" != "$(stat -c %d "$HOME_ROOT")" ]]; then
        warn "home kept in place: ${home} (a separate file system); make it root's by hand: chown -hR root:root ${home}"
        return 0
    fi
    if [[ -e "$dest" || -L "$dest" ]]; then
        warn "home kept in place: ${home} (${dest} exists)."
        return 0
    fi
    if ! { { [[ -d "$REMOVED_DIR" ]] || mkdir -m 0700 "$REMOVED_DIR"; } && chown root:root "$REMOVED_DIR" && chmod 0700 "$REMOVED_DIR"; }; then
        warn "home kept in place: ${home} (${REMOVED_DIR} could not be prepared)."
        return 0
    fi
    if ! mv -T -- "$home" "$dest"; then
        warn "home kept in place: ${home} (it could not be moved to ${REMOVED_DIR})."
        return 0
    fi
    if ! { chown -hR root:root -- "$dest" && chmod 0700 "$dest"; }; then
        warn "home kept: ${dest}, but it could not all be made root's; check it: chown -hR root:root ${dest}"
        return 0
    fi
    info "home kept: ${dest}"
}

existing=$(getent passwd "$ACCOUNT" || true)

# Only the grant: an adopted account whose proof failed stays, without sudo.
if [[ "$SUDOERS_ONLY" == "1" ]]; then
    sudoers_drop || die "The sudoers line of '${ACCOUNT}' could not be taken out of ${SUDOERS_FILE}."
    info "Took the sudoers line of '${ACCOUNT}' out of ${SUDOERS_FILE}; the account itself was left."
    exit 0
fi

if [[ -z "$existing" ]]; then
    sudoers_drop
    state_forget
    info "There is no account '${ACCOUNT}' on this host; nothing to remove there."
    exit 0
fi
uid=$(cut -d: -f3 <<< "$existing")
pgid=$(cut -d: -f4 <<< "$existing")
home=$(cut -d: -f6 <<< "$existing")
if [[ "$ACCOUNT" == "root" || "$uid" == "0" ]]; then
    die "Refusing to remove '${ACCOUNT}' (UID ${uid}). Nothing was changed."
fi
if uid_forbidden "$uid"; then
    die "The account '${ACCOUNT}' has UID ${uid}, inside tacctl's UID range or one it used before: it belongs to 'host sync'. Nothing was changed."
fi
if [[ "${SUDO_USER:-}" == "$ACCOUNT" ]]; then
    die "This session is logged in as '${ACCOUNT}'. Nothing was changed."
fi

# Grants other than the provisioning line stay, and are said.
for g in sudo wheel admin; do
    case " $(id -nG "$ACCOUNT" 2>/dev/null || true) " in
        *" $g "*) warn "'${ACCOUNT}' was in the group '${g}' (it leaves with the account)." ;;
    esac
done
# shellcheck disable=SC2086
others=$({ grep -lE "^${ACCOUNT}[[:space:]]" $SUDOERS_SCAN 2>/dev/null | grep -vxF "$SUDOERS_FILE"; } || true)
if [[ -n "$others" ]]; then
    warn "These sudoers files name '${ACCOUNT}' and were left as they are: ${others//$'\n'/ }"
fi

refusal=""
if [[ -e "$home" || -L "$home" ]] && [[ -n "$home" && "$home" != "/" ]]; then
    refusal=$(home_refusal "$ACCOUNT" "$uid" "$home")
fi

# The grant goes first: if userdel cannot run, the account is at least
# without sudo (and expired, below).
sudoers_drop || die "The sudoers line of '${ACCOUNT}' could not be taken out of ${SUDOERS_FILE}; nothing else was changed."
usermod -e 1 "$ACCOUNT" || true
if command -v pkill >/dev/null 2>&1; then
    pkill -TERM -u "$ACCOUNT" || true
    sleep 1
    pkill -KILL -u "$ACCOUNT" || true
fi
if ! userdel "$ACCOUNT"; then
    die "Could not delete '${ACCOUNT}' (userdel failed; still logged in?). Its sudoers line is gone and the account is expired; remove it by hand: userdel ${ACCOUNT}"
fi
group=$(getent group "$ACCOUNT" || true)
if [[ -n "$group" ]]; then
    gid=$(cut -d: -f3 <<< "$group"); members=$(cut -d: -f4 <<< "$group")
    if [[ "$gid" == "$uid" || "$gid" == "$pgid" ]] && [[ -z "$members" && -z "$(getent passwd | awk -F: -v g="$gid" '$4 == g { print $1; exit }')" ]]; then
        groupdel "$ACCOUNT" || true
    fi
fi
state_forget
info "Deleted the account '${ACCOUNT}' (UID ${uid})."

if [[ -z "$home" || "$home" == "/" ]]; then exit 0; fi
if [[ "$REMOVE_HOME" == "1" && -z "$refusal" && -d "$home" ]]; then
    rm -rf --one-file-system -- "$home"
    info "Deleted home ${home}."
elif [[ -n "$refusal" ]]; then
    warn "home kept in place: ${home} (${refusal})"
elif [[ -e "$home" || -L "$home" ]]; then
    keep_home "$ACCOUNT" "$home"
fi
