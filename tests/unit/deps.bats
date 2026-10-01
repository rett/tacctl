#!/usr/bin/env bats
# Unit tests for ensure_dependencies (packages installed by install/upgrade)
# and the OS-to-container-image mapping used by 'host enroll'.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    tacctl_source_lib
}

# dpkg-query stand-in: packages named in $HAVE are installed.
_dpkg() {
    export HAVE="$1"
    stub_cmd dpkg-query '[[ " $HAVE " == *" ${@: -1} "* ]] && echo "install ok installed"'
}

@test "ensure_dependencies: installs nothing when everything is present" {
    _dpkg "$DEPS_CORE $DEPS_LINUX_HOSTS"
    stub_cmd apt-get
    run ensure_dependencies
    assert_success
    assert_output --partial "all present"
    run grep -c "^apt-get" "$CALLS_LOG"
    assert_output "0"
}

@test "ensure_dependencies: installs only what is missing" {
    _dpkg "${DEPS_CORE} ${DEPS_LINUX_HOSTS/podman uidmap/}"
    stub_cmd apt-get
    run ensure_dependencies
    assert_success
    stub_called "apt-get install -y -qq podman uidmap$"
}

@test "ensure_dependencies: a missing core package that cannot be installed is fatal" {
    _dpkg "${DEPS_CORE/python3-bcrypt/} $DEPS_LINUX_HOSTS"
    stub_cmd apt-get 'exit 100'
    run ensure_dependencies
    assert_failure
    assert_output --partial "Could not install: python3-bcrypt"
    stub_called "apt-get update"
}

@test "ensure_dependencies: missing Linux-host packages only warn" {
    _dpkg "$DEPS_CORE"
    stub_cmd apt-get 'exit 100'
    run ensure_dependencies
    assert_success
    assert_output --partial "everything else works"
}

@test "linux_image_for_os: maps Ubuntu, derivatives and Debian; rejects the rest" {
    run linux_image_for_os $'ID=ubuntu\nVERSION_CODENAME=jammy'
    assert_output "docker.io/library/ubuntu:jammy"
    run linux_image_for_os $'ID=linuxmint\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME=noble'
    assert_output "docker.io/library/ubuntu:noble"
    run linux_image_for_os $'ID=debian\nVERSION_CODENAME="bookworm"'
    assert_output "docker.io/library/debian:bookworm"
    run linux_image_for_os $'ID="rocky"\nVERSION_ID="9.4"'
    assert_output ""
    run linux_image_for_os $'ID=ubuntu\nVERSION_CODENAME=noble;reboot'
    assert_output ""
}
