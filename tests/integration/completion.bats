#!/usr/bin/env bats
# Bash completion for the backend, store, log --backend, config listen,
# user scope and scope vendor-attrs / devices / auth-method words
# (config/tacctl.bash-completion), and the hidden '_completion-names' kinds it
# asks the sudo bridge for. The completion function runs in a bash of its own
# with the real bash-completion library; 'sudo' is a stub that answers the
# bridge's questions.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

COMPLETION="${BATS_TEST_DIRNAME}/../../config/tacctl.bash-completion"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    [[ -r /usr/share/bash-completion/bash_completion ]] || skip "bash-completion not installed"
    # The bridge: 'sudo -n tacctl _completion-names <kind> [arg]'.
    stub_cmd sudo 'case "$*" in
  *"_completion-names backends")         printf "%s\n" tacacs radius ;;
  *"_completion-names enabled-backends") printf "%s\n" tacacs ;;
  *"_completion-names listeners radius") printf "%s\n" auth acct ;;
  *"_completion-names listeners")        printf "%s\n" default ;;
esac'
}

# complete <word>...: what the completion offers for that command line, one per
# line; the last word is the one being completed (empty string: a fresh word).
complete_words() {
    run bash -c '
        source /usr/share/bash-completion/bash_completion
        source "$1"; shift
        COMP_WORDS=("$@"); COMP_CWORD=$(( ${#COMP_WORDS[@]} - 1 ))
        COMP_LINE="${COMP_WORDS[*]}"; COMP_POINT=${#COMP_LINE}
        _tacctl "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}"
        printf "%s\n" "${COMPREPLY[@]}"
    ' _ "$COMPLETION" "$@"
}

@test "completion: the top level offers backend and store" {
    complete_words tacctl ""
    assert_line "backend"
    assert_line "store"
    complete_words tacctl ba
    assert_output "$(printf 'backend\nbackup')"
}

@test "completion: backend subcommands, then backend ids, then -y" {
    complete_words tacctl backend ""
    assert_output "$(printf 'list\nstatus\nenable\ndisable')"
    complete_words tacctl backend enable ""
    assert_output "$(printf 'tacacs\nradius')"
    complete_words tacctl backend status r
    assert_output "radius"
    complete_words tacctl backend disable ""
    assert_output "tacacs"
    complete_words tacctl backend enable radius ""
    assert_output "$(printf -- '-y\n--yes')"
    complete_words tacctl backend list ""
    assert_output ""
}

@test "completion: store subcommands and their flags" {
    complete_words tacctl store ""
    assert_output "$(printf 'show\nimport\nrollback')"
    complete_words tacctl store show -
    assert_output "--json"
    complete_words tacctl store import --
    assert_output "$(printf -- '--check\n--force\n--replace')"
}

@test "completion: config offers render, and listen takes --backend and --listener" {
    complete_words tacctl config ren
    assert_output "render"
    complete_words tacctl config render ""
    assert_output "--force"
    complete_words tacctl config listen ""
    assert_line "--backend"
    assert_line "--listener"
    assert_line "reset"
    complete_words tacctl config listen --backend ""
    assert_output "$(printf 'tacacs\nradius')"
    complete_words tacctl config listen --backend radius --listener ""
    assert_output "$(printf 'auth\nacct')"
    complete_words tacctl config listen --listener ""
    assert_output "default"
    complete_words tacctl config listen --backend radius ""
    assert_line "--listener"
    refute_line "--backend"
}

@test "completion: config cisco and juniper take --protocol, and its value is tacacs or radius" {
    complete_words tacctl config cisco ""
    assert_output "$(printf -- '--scope\n--legacy\n--protocol')"
    complete_words tacctl config juniper ""
    assert_output "$(printf -- '--scope\n--protocol')"
    complete_words tacctl config cisco --protocol ""
    assert_output "$(printf 'tacacs\nradius')"
    complete_words tacctl config juniper --scope lab --protocol ""
    assert_output "$(printf 'tacacs\nradius')"
    complete_words tacctl config juniper --scope lab ""
    assert_output "--protocol"
    complete_words tacctl config cisco --protocol radius ""
    assert_output "$(printf -- '--scope\n--legacy')"
    complete_words tacctl config cisco --protocol radius --scope lab ""
    assert_output "--legacy"
    # WTI takes --protocol like the others.
    complete_words tacctl config wti ""
    assert_output "$(printf -- '--scope\n--protocol')"
    complete_words tacctl config wti --protocol ""
    assert_output "$(printf 'tacacs\nradius')"
    complete_words tacctl config wti --scope lab ""
    assert_output "--protocol"
}

@test "completion: scope offers radius-group beside tacacs-group" {
    complete_words tacctl scope radius
    assert_output "radius-group"
}

@test "completion: scope offers auth-method, a scope name, then tacacs, radius or clear" {
    complete_words tacctl scope auth
    assert_output "auth-method"
    complete_words tacctl scope auth-method lab ""
    assert_output "$(printf 'tacacs\nradius\nclear')"
}

@test "completion: scope vendor-attrs offers enable and disable (no set, clear or none), then vendors" {
    complete_words tacctl scope vend
    assert_output "vendor-attrs"
    complete_words tacctl scope vendor-attrs lab ""
    assert_output "$(printf 'enable\ndisable')"
    complete_words tacctl scope vendor-attrs lab enable ""
    assert_line "cisco"
    assert_line "juniper"
    assert_line "wti"
    complete_words tacctl scope vendor-attrs lab disable w
    assert_output "wti"
}

@test "completion: scope devices offers list, set and unset, and a vendor after set's address" {
    complete_words tacctl scope dev
    assert_output "devices"
    complete_words tacctl scope devices lab ""
    assert_output "$(printf 'list\nset\nunset')"
    complete_words tacctl scope devices lab set 10.1.2.3 ""
    assert_output "$(printf 'cisco\njuniper\nwti')"
    complete_words tacctl scope devices lab unset 10.1.2.3 ""
    assert_output ""
}

@test "completion: scope add offers --protocols and --vendor-attrs, with their values" {
    complete_words tacctl scope add edge ""
    assert_output "$(printf -- '--prefixes\n--secret\n--protocols\n--vendor-attrs\n--default')"
    complete_words tacctl scope add edge --prefixes 10.0.0.0/8 --vendor-attrs ""
    assert_line "cisco"
    assert_line "cisco,juniper,wti"
    complete_words tacctl scope add edge --prefixes 10.0.0.0/8 --vendor-attrs cisco ""
    assert_output "$(printf -- '--secret\n--protocols\n--default')"
}

@test "completion: log subcommands take --backend, and its value is a backend id" {
    complete_words tacctl log tail --
    assert_output "--backend"
    complete_words tacctl log tail --backend ""
    assert_output "$(printf 'tacacs\nradius')"
    complete_words tacctl log clear ""
    assert_output "$(printf -- '--backend\n--force')"
    complete_words tacctl log clear --backend tacacs ""
    assert_output "--force"
}

@test "completion: scope protocols still completes its verbs and the protocols" {
    complete_words tacctl scope protocols lab ""
    assert_output "$(printf 'list\nset\nclear')"
    complete_words tacctl scope protocols lab set ""
    assert_line "tacacs"
    assert_line "radius"
}

@test "completion: scope prefixes offers remove (no clear), then --all, then --force only after --all" {
    complete_words tacctl scope prefixes lab ""
    assert_output "$(printf 'list\nadd\nremove')"
    complete_words tacctl scope prefixes lab remove ""
    assert_output -- "--all"
    complete_words tacctl scope prefixes lab remove --all ""
    assert_output -- "--force"
    complete_words tacctl scope prefixes lab remove 10.0.0.0/8 ""
    assert_output ""
    complete_words tacctl scope prefixes lab add ""
    assert_output ""
}

@test "completion: user scope offers replace and remove --all (no set or clear), then scope names" {
    stub_cmd sudo 'case "$*" in
  *"_completion-names scopes") printf "%s\n" lab prod ;;
esac'
    complete_words tacctl user scope alice ""
    assert_output "$(printf 'list\nadd\nremove\nreplace')"
    complete_words tacctl user scope alice remove ""
    assert_output "$(printf -- '--all\nlab\nprod')"
    complete_words tacctl user scope alice remove --all ""
    assert_output ""
    complete_words tacctl user scope alice replace ""
    assert_output "$(printf 'lab\nprod')"
    complete_words tacctl user scope alice add ""
    assert_output "$(printf 'lab\nprod')"
}

@test "completion: config linux script flags and methods, builds, backup restore --legacy" {
    complete_words tacctl config linux ""
    assert_output "$(printf 'build\nscript\nremove-script\nuid\nbuilds')"
    complete_words tacctl config linux script ""
    assert_output "$(printf -- '--scope\n--server\n--method\n--output')"
    complete_words tacctl config linux script --method ""
    assert_output "$(printf 'tacplus\nradius')"
    complete_words tacctl config linux builds ""
    assert_output "$(printf 'list\nclear')"
    complete_words tacctl backup restore 20260101-000000 ""
    assert_output -- "--legacy"
    complete_words tacctl config restore 20260101-000000 ""
    assert_output -- "--legacy"
    complete_words tacctl host default-method ""
    assert_output "$(printf 'tacplus\nradius')"
}

@test "completion: user, group and scope names come from the sudo bridge only, never from tacquito.yaml" {
    # A rendered tacquito.yaml lacks the scopes TACACS+ does not serve.
    stub_cmd sudo 'case "$*" in
  *"_completion-names scopes") printf "%s\n" lab radius-only ;;
esac'
    complete_words tacctl scope show ""
    assert_output "$(printf 'lab\nradius-only')"
    run grep -c '/etc/tacquito' "$COMPLETION"
    assert_output "0"
}

# --- the names the bridge asks tacctl for ---------------------------------------

@test "_completion-names: backends are every registered id, enabled-backends the enabled ones, listeners a backend's" {
    load_fixture tacquito.minimal.yaml
    run "$TACCTL_BIN_SCRIPT" _completion-names backends
    assert_success
    assert_output "$(printf 'tacacs\nradius')"
    run "$TACCTL_BIN_SCRIPT" _completion-names enabled-backends
    assert_output "tacacs"
    run "$TACCTL_BIN_SCRIPT" _completion-names listeners
    assert_output "$(printf 'acct\nauth\ndefault')"
    run "$TACCTL_BIN_SCRIPT" _completion-names listeners radius
    assert_output "$(printf 'acct\nauth')"
    "$TACCTL_BIN_SCRIPT" config listen --listener mgmt tcp 127.0.0.1:4949 > /dev/null
    run "$TACCTL_BIN_SCRIPT" _completion-names listeners tacacs
    assert_output "$(printf 'default\nmgmt')"
    run "$TACCTL_BIN_SCRIPT" _completion-names listeners nope
    assert_success
    assert_output ""
}
