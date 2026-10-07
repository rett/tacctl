#!/usr/bin/env bash
# PATH-based command stubs for mocking external tools (systemctl, git, etc.).
# Requires $BATS_TEST_TMPDIR; call tacctl_mocks_init first.

tacctl_mocks_init() {
    export STUB_BIN="${BATS_TEST_TMPDIR}/stubs"
    export CALLS_LOG="${BATS_TEST_TMPDIR}/calls.log"
    mkdir -p "${STUB_BIN}"
    : > "${CALLS_LOG}"
    # Prepend stub dir so test stubs shadow real binaries.
    export PATH="${STUB_BIN}:${PATH}"
    # tacctl reads host keys with ssh-keyscan (device add, host enroll and
    # sync): no test may reach a real host, so by default nothing answers.
    # A test that wants keys stubs it with stub_cmd, which also logs calls.
    printf '#!/usr/bin/env bash\nexit 0\n' > "${STUB_BIN}/ssh-keyscan"
    chmod +x "${STUB_BIN}/ssh-keyscan"
}

# stub_cmd <name> <body>
# <body> is bash executed when the stub is invoked. The stub records its
# argv to $CALLS_LOG (one line per call: "<name> <arg1> <arg2> ...").
stub_cmd() {
    local name="$1"
    local body="${2:-exit 0}"
    local path="${STUB_BIN}/${name}"
    cat > "${path}" <<STUB
#!/usr/bin/env bash
echo "${name} \$*" >> "${CALLS_LOG}"
${body}
STUB
    chmod +x "${path}"
}

# Return 0 if the calls log contains a line matching the given regex.
stub_called() {
    local pattern="$1"
    grep -qE "${pattern}" "${CALLS_LOG}"
}

# Dump the calls log (useful in test failure output).
stub_calls() {
    cat "${CALLS_LOG}"
}
