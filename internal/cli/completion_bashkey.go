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
# words before the cursor, the text the shell's question mark prints, in colour
# on a terminal, and leaves the line as it is; anywhere else it types a
# question mark. The key runs only 'tacctl __help -- <words>', which prints and
# runs nothing else: the words are plain words to it, never a flag or a verb.
# TACCTL_HELP_KEY, read when this file is sourced, changes the key: unset or
# '?' is the question mark, a readline key spelling such as '\eh' is that key
# (which then does nothing outside a tacctl line), 'off' binds nothing.
__tacctl_help_key() {
    local IFS=$' \t\n'
    local blank=$' \t'
    local before=${READLINE_LINE:0:READLINE_POINT}
    local -a words
    local n
    # Plain words only: a quote, a backslash, a shell operator, any other
    # character than the letters, digits, spaces, tabs and _ @ % + = : , . / -
    # before the cursor (a carriage return, a second line) means the line is
    # not asked about, and the key types itself.
    if [[ $before =~ ^[$blank]*tacctl([$blank]|$) &&
        ! $before =~ [^A-Za-z0-9_@%+=:,./$blank-] ]]; then
        read -ra words <<<"$before"
        # The words after tacctl, without the word being typed.
        n=$((${#words[@]} - 1))
        if [[ $before == *[!$blank] ]]; then
            n=$((n - 1))
        fi
        if ((n > 0)); then
            words=("${words[@]:1:n}")
        else
            words=()
        fi
        printf '\n'
        command tacctl __help -- ${words[@]+"${words[@]}"}
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
