#!/usr/bin/env bats
# Integration tests for `tacctl device reports generate --format pdf`: the
# report is turned into a PDF by an external tool (weasyprint), which a test
# build lets TACCTL_TEST_PDF_TOOL replace with a stub that writes %PDF-1.7 and
# copies its standard input. The stored reports need a Linux account for the
# user (the account database of this machine), which a test has no way to
# make, so storing, listing and the other verbs of the family are Go tests
# (internal/cli/device_reports_pdf_test.go, device_reports_pdf_family_test.go);
# --stdout needs no account.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.multiscope.yaml
    "$TACCTL_BIN_SCRIPT" device add lab-sw1 192.168.1.11 --vendor cisco --no-lookup --no-host-key > /dev/null
    "$TACCTL_BIN_SCRIPT" device add lab-sw2 192.168.1.12 --vendor juniper --no-lookup --no-host-key > /dev/null
    SUDO_USER=alice "$TACCTL_BIN_SCRIPT" device description lab-sw1 '<script>alert(1)</script> & "quotes"' > /dev/null
    PDF_STUB="${BATS_TEST_TMPDIR}/weasyprint-stub"
    cat > "$PDF_STUB" <<'STUB'
#!/bin/sh
printf '%s\n' "$*" > "$0.args"
env | sort > "$0.env"
printf '%%PDF-1.7\n'
cat
STUB
    chmod +x "$PDF_STUB"
}

alice() {
    SUDO_USER=alice run "$TACCTL_BIN_SCRIPT" "$@"
}

@test "pdf: --stdout writes what the tool made, from the escaped report" {
    TACCTL_TEST_PDF_TOOL="$PDF_STUB" alice device reports generate --type inventory --format pdf --stdout
    assert_success
    [[ "${lines[0]}" == "%PDF-1.7" ]]
    assert_output --partial "<title>Device inventory report</title>"
    assert_output --partial "<td>lab-sw1</td>"
    assert_output --partial "&lt;script&gt;alert(1)&lt;/script&gt; &amp; &#34;quotes&#34;"
    refute_output --partial "<script"
    refute_output --partial "@import"
    refute_output --partial "url("
    refute_output --partial "<link"
    refute_output --partial "<img"
    # the tool was run as documented, with an environment of its own
    [[ "$(cat "${PDF_STUB}.args")" == "--quiet - -" ]]
    run cat "${PDF_STUB}.env"
    assert_output --partial "LANG=C.UTF-8"
    assert_output --partial "XDG_CACHE_HOME="
    assert_output --partial "PATH=/usr/local/bin:/usr/bin:/bin"
    refute_output --partial "TACCTL_"
    refute_output --partial "SUDO_USER"
}

@test "pdf: every type makes a document with its own columns" {
    for typ in inventory members software config; do
        TACCTL_TEST_PDF_TOOL="$PDF_STUB" alice device reports generate --type "$typ" --format pdf --stdout
        assert_success
        assert_output --partial "<title>Device ${typ} report</title>"
    done
    TACCTL_TEST_PDF_TOOL="$PDF_STUB" alice device reports generate --type software --vendor cisco --format pdf --stdout
    assert_success
    assert_output --partial "<dt>Filters</dt><dd>vendor=cisco</dd>"
    assert_output --partial "<td>lab-sw1</td>"
    refute_output --partial "lab-sw2"
}

@test "pdf: a missing tool refuses first, with the fix" {
    TACCTL_TEST_PDF_TOOL="${BATS_TEST_TMPDIR}/no-such-tool" alice device reports generate --type inventory --format pdf --stdout
    assert_failure 1
    assert_output --partial "[ERROR] PDF reports need weasyprint, which is not installed here. Install it: sudo apt-get install -y weasyprint fonts-dejavu-core"
    refute_output --partial "%PDF"
    refute_output --partial "lab-sw1"
}

@test "pdf: a tool that fails, or makes no PDF, writes nothing and says why" {
    cat > "${BATS_TEST_TMPDIR}/failing" <<'STUB'
#!/bin/sh
cat > /dev/null
echo "ERROR: cannot lay out the table" >&2
echo "<td>lab-sw1</td> quoted" >&2
exit 3
STUB
    chmod +x "${BATS_TEST_TMPDIR}/failing"
    TACCTL_TEST_PDF_TOOL="${BATS_TEST_TMPDIR}/failing" alice device reports generate --type inventory --format pdf --stdout
    assert_failure 1
    assert_output --partial "Cannot make the PDF: the PDF tool (weasyprint) failed with exit status 3: ERROR: cannot lay out the table."
    assert_output --partial "Nothing was written."
    refute_output --partial "<td>"
    refute_output --partial "%PDF"
    cat > "${BATS_TEST_TMPDIR}/nopdf" <<'STUB'
#!/bin/sh
cat > /dev/null
echo "hello"
STUB
    chmod +x "${BATS_TEST_TMPDIR}/nopdf"
    TACCTL_TEST_PDF_TOOL="${BATS_TEST_TMPDIR}/nopdf" alice device reports generate --type inventory --format pdf --stdout
    assert_failure 1
    assert_output --partial "the PDF tool (weasyprint) made no PDF"
}

@test "pdf: the usage and the format check name the format" {
    alice device reports generate --type inventory --format docx
    assert_failure 2
    assert_output --partial "Unknown report format 'docx' (valid formats: text, csv, json, pdf)."
    alice device reports
    assert_success
    assert_output --partial "[--format text|csv|json|pdf]"
    assert_output --partial "<name>.<txt|csv|json|pdf>"
}
