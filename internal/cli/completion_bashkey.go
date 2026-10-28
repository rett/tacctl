package cli

// The help key of the bash script. 'tacctl completion bash' prints cobra's
// generated script and, after it, this block: it binds the question mark (or
// the key TACCTL_HELP_KEY names) with 'bind -x' so that on a line that
// starts with tacctl it prints the help of the words before the cursor, the
// text the shell's '?' prints ('tacctl <words> --help', help_request.go),
// and leaves the command line as it is. Anywhere else the question mark
// types itself, so 'ls *.?' still works.

import "strings"

// bashHelpKey is the block appended to the generated bash script. Keep it
// shellcheck-clean (TestBashHelpKeyBlockIsShellcheckClean).
const bashHelpKey = `
# --- tacctl help key -----------------------------------------------------------
# The question mark on a line that starts with tacctl prints the help of the
# words before the cursor ('tacctl <words> --help': in colour on a terminal)
# and leaves the line as it is; anywhere else it types a question mark.
# TACCTL_HELP_KEY, read when this file is sourced, changes the key: unset or
# '?' is the question mark, a readline key spelling such as '\eh' is that key
# (which then does nothing outside a tacctl line), 'off' binds nothing.
__tacctl_help_key() {
    local IFS=$' \t\n'
    local before=${READLINE_LINE:0:READLINE_POINT}
    local -a words
    # Plain words only: a quote, a backslash, a shell operator or a second line
    # before the cursor means the line is not asked about, and the key types
    # itself.
    if [[ $before =~ ^[[:space:]]*tacctl([[:space:]]|$) && $before != *$'\n'* &&
        ! $before =~ [^A-Za-z0-9_@%+=:,./[:space:]-] ]]; then
        read -ra words <<<"$before"
        words=("${words[@]:1}")
        # The word being typed is not part of the question.
        if [[ $before == *[![:space:]] && ${#words[@]} -gt 0 ]]; then
            unset 'words[-1]'
        fi
        printf '\n'
        command tacctl "${words[@]}" --help
        return 0
    fi
    [[ $__tacctl_help_key_word == '?' ]] || return 0
    READLINE_LINE="${READLINE_LINE:0:READLINE_POINT}?${READLINE_LINE:READLINE_POINT}"
    READLINE_POINT=$((READLINE_POINT + 1))
}

__tacctl_bind_help_key() {
    [[ $- == *i* ]] || return 0
    __tacctl_help_key_word=${TACCTL_HELP_KEY:-?}
    case $__tacctl_help_key_word in
    off | *'"'* | *$'\n'*) return 0 ;;
    esac
    bind -x "\"$__tacctl_help_key_word\": __tacctl_help_key" 2>/dev/null
}
__tacctl_bind_help_key
`

// bashScript is the text of the bash completion script: cobra's generated
// part and the help key.
func bashScript(generated string) string {
	return strings.TrimRight(generated, "\n") + "\n" + bashHelpKey
}
