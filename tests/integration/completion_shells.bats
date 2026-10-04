#!/usr/bin/env bats
# bats file_tags=requires-zsh-fish
# zsh and fish completion, in a real zsh and a real fish: the scripts
# 'tacctl completion zsh|fish' print must parse and must answer with the words
# the binary gives ('tacctl __complete'). These tests do not skip: without the
# shell they fail and name the package to install ('apt install zsh fish').
# The Makefile leaves the tag out of 'make test-bats' until the shells are on
# the machine (BATS_TAG_FLAGS).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd tacctl "exec \"${TACCTL_BIN_SCRIPT}\" \"\$@\""
    stub_cmd sudo 'case "$*" in
  *"_completion-names scopes") printf "%s\n" lab prod ;;
esac'
}

need() {
    command -v "$1" > /dev/null 2>&1 || {
        echo "$1 is not installed: apt install $1 (the zsh and fish completion tests need it)" >&2
        return 1
    }
}

@test "zsh: the script parses (zsh -n) and registers _tacctl" {
    need zsh
    "$TACCTL_BIN_SCRIPT" completion zsh > "${BATS_TEST_TMPDIR}/_tacctl"
    run zsh -n "${BATS_TEST_TMPDIR}/_tacctl"
    assert_success
    assert_output ""
    run grep -c '^#compdef tacctl$' "${BATS_TEST_TMPDIR}/_tacctl"
    assert_output "1"
}

# zsh_complete <words...>: the candidates _tacctl hands to _describe for that
# command line, one per line (the last word is the one being completed).
# _describe is replaced by a function that prints its candidates; the
# function itself is the one the script generated, loaded through compinit.
zsh_complete() {
    run zsh -f -c '
        autoload -Uz compinit && compinit -u -d "$1/zcompdump" || exit 1
        source <("$2" completion zsh) || exit 1
        (( $+functions[_tacctl] )) || { print -u2 "_tacctl not defined"; exit 1; }
        [[ ${_comps[tacctl]} == _tacctl ]] || { print -u2 "tacctl not registered"; exit 1; }
        _describe() {
            local a name; local -a pos
            for a in "$@"; do [[ $a == -* ]] || pos+=("$a"); done
            name=$pos[2]
            print -rl -- "${(@P)name}"
        }
        shift 2
        words=("$@"); CURRENT=$#words
        _tacctl
    ' zsh "$BATS_TEST_TMPDIR" "$TACCTL_BIN_SCRIPT" "$@"
}

@test "zsh: completing 'tacctl us' offers user" {
    need zsh
    zsh_complete tacctl us
    assert_success
    assert_line --regexp '^user(:|$)'
    refute_line --regexp '^scope(:|$)'
}

@test "zsh: names come from the sudo bridge" {
    need zsh
    zsh_complete tacctl scope show l
    assert_success
    assert_line "lab"
}

@test "fish: the script parses (fish -n)" {
    need fish
    "$TACCTL_BIN_SCRIPT" completion fish > "${BATS_TEST_TMPDIR}/tacctl.fish"
    run fish -n "${BATS_TEST_TMPDIR}/tacctl.fish"
    assert_success
    assert_output ""
}

# fish_complete <command line>: what fish completes for it, one candidate
# (and its description, after a tab) per line.
fish_complete() {
    mkdir -p "${BATS_TEST_TMPDIR}/fishhome"
    HOME="${BATS_TEST_TMPDIR}/fishhome" XDG_CONFIG_HOME="${BATS_TEST_TMPDIR}/fishhome/.config" \
        run fish --no-config -c '
        tacctl completion fish | source
        complete -C "$argv[1]"
    ' "$1"
}

@test "fish: completing 'tacctl us' offers user" {
    need fish
    fish_complete 'tacctl us'
    assert_success
    assert_line --regexp '^user($|'$'\t'')'
    refute_line --regexp '^scope($|'$'\t'')'
}

@test "fish: names come from the sudo bridge" {
    need fish
    fish_complete 'tacctl scope show l'
    assert_success
    assert_line --regexp '^lab($|'$'\t'')'
}
