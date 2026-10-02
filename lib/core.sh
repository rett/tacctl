# shellcheck shell=bash
# shellcheck disable=SC2034  # constants assigned here are read by the other lib files
# tacctl lib/core.sh -- paths, constants, output helpers, version, preflight, shared validators and CIDR helpers
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.

# Base paths: overridable via env for tests and non-standard deployments.
# Production defaults are unchanged.
: "${TACCTL_ETC:=/etc/tacquito}"
: "${TACCTL_LOG:=/var/log/tacquito}"
: "${TACCTL_BIN:=/usr/local/bin}"
: "${TACCTL_CONFIG:=${TACCTL_ETC}/tacquito.yaml}"

CONFIG="${TACCTL_CONFIG}"
BACKUP_DIR="${TACCTL_ETC}/backups"
PASSWORD_DATES_DIR="${TACCTL_ETC}/backups/password-dates"
ACCT_LOG="${TACCTL_LOG}/accounting.log"
PASSWORD_MAX_AGE_DAYS=90
BCRYPT_COST=12
PASSWORD_MIN_LENGTH=12
SECRET_MIN_LENGTH=16
CISCO_ACL_NAME_DEFAULT="VTY-ACL"
JUNIPER_ACL_NAME_DEFAULT="MGMT-ACL"
DEFAULT_SCOPE_FRESH="lab"  # name used on fresh installs; upgrades keep existing scope name
CONFIG_DIR="${TACCTL_ETC}"
LOG_DIR="${TACCTL_LOG}"
SERVICE_FILE="/etc/systemd/system/tacquito.service"

# Unified tacctl config: canonical defaults live in conf_emit_defaults();
# operator overrides live in this one on-disk file.
TACCTL_OVERRIDES_FILE="${TACCTL_ETC}/tacctl.yaml"

# --- System lifecycle constants ---
GO_VERSION="1.26.2"
TACQUITO_REPO="https://github.com/facebookincubator/tacquito.git"
# Overridable so tests can point the patch overlay at a scratch checkout.
TACQUITO_SRC="${TACQUITO_SRC:-/opt/tacquito-src}"
TACQUITO_BIN="${TACCTL_BIN}/tacquito"
HASHGEN_BIN="${TACCTL_BIN}/tacquito-hashgen"
DEPLOY_DIR="/opt/tacctl"
MANAGE_REPO="https://github.com/rett/tacctl.git"
GO_BIN="/usr/local/go/bin/go"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Version (resolved from the git repo that holds this script) ---
get_version() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
    git -C "${script_dir}/.." describe --tags --always --dirty 2>/dev/null || echo "unknown"
}

# --- Pre-flight ---
preflight() {
    if [[ ! -f "$CONFIG" ]]; then
        error "Config not found at ${CONFIG}. Is tacquito installed?"
        exit 1
    fi
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        error "python3-bcrypt not installed. Install it first."
        exit 1
    fi
}

# --- Validate class/value names ---
validate_class_name() {
    local value="$1"
    if [[ ! "$value" =~ ^[A-Za-z0-9_-]+$ ]]; then
        error "Invalid name '${value}'. Only letters, numbers, underscores, and hyphens are allowed."
        exit 1
    fi
}

# --- Validate username ---
# Shape only (letters/digits/_/-). See reject_reserved_username() for the
# names-reserved check — that lives on the creation path only, so cleanup
# operations like `tacctl user remove root` can still reach a legacy entry.
validate_username() {
    local value="$1"
    if [[ ! "$value" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error "Username must contain only letters, numbers, underscores, and hyphens."
        exit 1
    fi
}

# Reserved OS / service names can't be tacctl-managed: 'root' is the OS
# root account and 'tacquito' is the service's own user. Both exist outside
# the YAML — letting tacctl manage either produces acct.go errors at auth
# time ('user [X] does not have an accounter associated') because tacquito
# resolves the username against the local account, not the tacctl entry.
reject_reserved_username() {
    local value="$1"
    case "$value" in
        root)
            error "Username 'root' is reserved as an accounting-only sink for Junos internal daemons (non-tty CLI as root)."
            error "The hash stays disabled permanently — root must only be used for local/console login, never TACACS+."
            error "Create an operator-specific account instead (e.g. tacctl user add jsmith <group>)."
            exit 1
            ;;
        tacquito)
            error "Username 'tacquito' is reserved (matches the service user). Pick a different name."
            exit 1
            ;;
    esac
}

# --- Validate CIDR notation ---
validate_cidr() {
    local value="$1"
    if ! python3 -c "import ipaddress,sys; ipaddress.ip_network(sys.argv[1],strict=False)" "$value" 2>/dev/null; then
        error "Invalid CIDR: '${value}'"
        exit 1
    fi
}

# --- Echo the canonical string form of a CIDR (or empty on invalid) ---
# IPv4: `10.1.5.5/24` → `10.1.5.0/24` (host bits zeroed).
# IPv6: `2001:DB8::/32` → `2001:db8::/32` (lower-cased, compressed).
# Used to dedup equivalent representations and give YAML storage a
# single canonical representation.
canonicalize_cidr() {
    python3 -c "
import ipaddress, sys
try:
    n = ipaddress.ip_network(sys.argv[1], strict=False)
    print(n)
except (ValueError, IndexError):
    pass
" "$1" 2>/dev/null
}

# --- Sort a newline-separated CIDR list by specificity (most-specific first) ---
# Tie-break: IPv4 before IPv6, then numeric network address ascending.
# Non-CIDR input lines are dropped silently (caller should validate first).
sort_cidrs_by_specificity() {
    python3 -c "
import ipaddress, sys
lines = sys.stdin.read().splitlines()
def key(c):
    n = ipaddress.ip_network(c, strict=False)
    return (n.version, int(n.broadcast_address), int(n.network_address))
valid = []
for line in lines:
    s = line.strip()
    if not s:
        continue
    try:
        ipaddress.ip_network(s, strict=False)
        valid.append(s)
    except ValueError:
        continue
for c in sorted(valid, key=key):
    print(c)
"
}

# --- Parse a comma-separated CIDR list into newline-separated output ---
# Validates every entry (aborts on invalid). Trims whitespace. Canonicalizes
# each entry (host bits stripped, IPv6 lower-cased). Dedupes within the
# input on the canonical form. Empty input → empty output.
# Order matches input order (dedupe preserves first occurrence); callers
# that need sort-by-specificity apply it downstream at write time.
parse_cidr_list() {
    local input="$1"
    local seen=""
    local cidr canonical
    IFS=',' read -ra CIDRS <<< "$input"
    for cidr in "${CIDRS[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        [[ -z "$cidr" ]] && continue
        validate_cidr "$cidr"
        canonical=$(canonicalize_cidr "$cidr")
        [[ -z "$canonical" ]] && continue  # validate_cidr already errored; defensive
        # within-input dedupe on canonical form
        if ! printf '%s\n' "$seen" | grep -qxF "$canonical"; then
            seen+="${seen:+$'\n'}${canonical}"
        fi
    done
    echo "$seen"
}

