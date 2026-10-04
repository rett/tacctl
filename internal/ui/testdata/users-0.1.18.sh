# read_password_masked, validate_password_strength and prompt_password as
# lib/users.sh of the 0.1.18 tag has them: the reference prompt_test.go
# runs in bash and compares with the Go prompts.

read_password_masked() {
    local prompt="${1:-Password: }"
    local password="" char=""
    printf "%s" "$prompt" >&2
    while IFS= read -rsn1 char; do
        # Enter pressed
        if [[ -z "$char" ]]; then
            break
        fi
        # Backspace / delete
        if [[ "$char" == $'\x7f' || "$char" == $'\b' ]]; then
            if [[ -n "$password" ]]; then
                password="${password%?}"
                printf '\b \b' >&2
            fi
        else
            password+="$char"
            printf '*' >&2
        fi
    done
    echo "" >&2
    echo "$password"
}

validate_password_strength() {
    local password="$1"
    local username="${2:-}"

    if [[ "${#password}" -lt "$PASSWORD_MIN_LENGTH" ]]; then
        error "Password is ${#password} characters; minimum is ${PASSWORD_MIN_LENGTH}."
        return 1
    fi

    local lower="${password,,}"
    # Reject the usual suspects. Lowercase-fold first so variants ("Admin",
    # "ADMIN") all match. Not a dictionary check — just the handful that
    # dominate breach corpora.
    case "$lower" in
        admin|administrator|root|password|password1|passw0rd|\
        tacacs|tacacs+|tacplus|tacquito|\
        cisco|cisco123|juniper|juniper1|\
        changeme|welcome|welcome1|letmein|qwerty*|abc123*|\
        12345*|00000*|aaaaaa*)
            error "Password is on the common-weak list. Choose another."
            return 1
            ;;
    esac

    if [[ -n "$username" && "$lower" == "${username,,}" ]]; then
        error "Password must not equal the username."
        return 1
    fi

    return 0
}

prompt_password() {
    local username="${1:-}"
    local password=""
    password=$(read_password_masked "  Enter password (leave blank to auto-generate): ")
    if [[ -z "$password" ]]; then
        password=$(openssl rand -base64 18)
        echo -e "  Generated password: ${BOLD}${password}${NC}" >&2
    else
        if ! validate_password_strength "$password" "$username"; then
            exit 1
        fi
        local confirm=""
        confirm=$(read_password_masked "  Confirm password: ")
        if [[ "$password" != "$confirm" ]]; then
            echo -e "  ${RED}Passwords do not match.${NC}" >&2
            exit 1
        fi
    fi
    echo "$password"
}

