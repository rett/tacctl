#!/usr/bin/env bash
# no-private.sh [--rev <commit>] [--messages <rev-list args>...]
#
# Fails when a tracked file names someone's own infrastructure: a home
# directory (/home/<name>/, bar the /home/user/ and /home/u/ placeholders),
# or an address user@host under a real-world TLD (example.com/net/org,
# git@github.com, noreply addresses and ssh algorithm names are allowed). The repository is public; documentation
# says "the dev server", "the production host", admin@client.example.net.
#
# Extra extended regexes, one per line ('#' starts a comment), are read from
# $TACCTL_PRIVATE_PATTERNS, default ~/.config/tacctl/private-patterns. That
# file lives outside the repository because the names in it are the private
# part; it is matched case-insensitively.
#
#   (no option)        scan the working tree's tracked files (make lint)
#   --rev <commit>     scan that commit's tree instead (the pre-push hook)
#   --messages <args>  also scan the commit messages of 'git rev-list <args>'
set -euo pipefail

rev=""
msg_args=()
while (($#)); do
    case "$1" in
        --rev) rev="$2"; shift 2 ;;
        --messages) shift; msg_args=("$@"); break ;;
        *) echo "usage: $0 [--rev <commit>] [--messages <rev-list args>...]" >&2; exit 2 ;;
    esac
done

# Fuzz inputs and third-party code are not prose about anyone's hosts.
pathspec=(-- . ':!vendor' ':!go.sum' ':!internal/conf/testdata')

home_re='/home/[a-z_][a-z0-9_-]*/'
mail_re='[a-z0-9._%+-]+@([a-z0-9-]+\.)+(com|net|org|io|us|uk|de|dev|app|co|me|info|biz|edu|gov|ca|au|nz|eu|ai|cloud|xyz|tech|online|site|is)\b'
# ssh algorithm names (sk-ssh-ed25519@openssh.com, curve25519-sha256@libssh.org)
# have an address's shape and name no one.
allow_re='/home/(user|u)/|@([a-z0-9-]+\.)*example\.(com|net|org)\b|git@github\.com|noreply|@openssh\.com\b|@libssh\.org\b'

patterns_file="${TACCTL_PRIVATE_PATTERNS:-${XDG_CONFIG_HOME:-$HOME/.config}/tacctl/private-patterns}"
private=()
if [[ -r "$patterns_file" ]]; then
    while IFS= read -r line; do
        line="${line%%#*}"
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
        [[ -n "$line" ]] && private+=("$line")
    done < "$patterns_file"
fi

found=0
report() {
    # $1 = what, $2 = matching lines
    [[ -z "$2" ]] && return 0
    echo "no-private: $1:" >&2
    printf '%s\n' "$2" | sed 's/^/  /' >&2
    found=1
}

tree=()
[[ -n "$rev" ]] && tree=("$rev")

report "a home directory or a personal address" \
    "$(git grep -nIiE "$home_re|$mail_re" "${tree[@]}" "${pathspec[@]}" | grep -viE "$allow_re" || true)"

# LICENSE carries the copyright holder's name on purpose.
for re in "${private[@]}"; do
    report "matches a private pattern from $patterns_file" \
        "$(git grep -nIiE "$re" "${tree[@]}" "${pathspec[@]}" ':!LICENSE' || true)"
done

if ((${#msg_args[@]})); then
    while read -r c; do
        msg=$(git log -1 --format=%B "$c")
        hits=$(printf '%s\n' "$msg" | grep -iE "$home_re|$mail_re" | grep -viE "$allow_re" || true)
        for re in "${private[@]}"; do
            hits+=$(printf '%s\n' "$msg" | grep -iE "$re" || true)
        done
        report "commit message of $(git rev-parse --short "$c")" "$hits"
    done < <(git rev-list "${msg_args[@]}")
fi

if ((found)); then
    echo "no-private: replace these with roles or example.* placeholders." >&2
    exit 1
fi
