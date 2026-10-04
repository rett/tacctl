package ui

import (
	"bytes"
	"strings"
	"testing"
)

// The expected bytes are what lib/core.sh's info/warn/error print with
// 'echo -e' (the escape codes are pinned by many bats assertions).
func TestLines(t *testing.T) {
	var out, errb bytes.Buffer
	o := Output{Stdout: &out, Stderr: &errb}
	o.Info("Added user alice")
	o.Warn("careful")
	o.Infof("%d users", 3)
	o.Warnf("%s missing", "x")
	o.Error("User 'bob' does not exist.")
	o.Errorf("Invalid CIDR: '%s'", "1.2.3")
	wantOut := "\033[0;32m[INFO]\033[0m Added user alice\n" +
		"\033[1;33m[WARN]\033[0m careful\n" +
		"\033[0;32m[INFO]\033[0m 3 users\n" +
		"\033[1;33m[WARN]\033[0m x missing\n"
	wantErr := "\033[0;31m[ERROR]\033[0m User 'bob' does not exist.\n" +
		"\033[0;31m[ERROR]\033[0m Invalid CIDR: '1.2.3'\n"
	if out.String() != wantOut {
		t.Errorf("stdout = %q", out.String())
	}
	if errb.String() != wantErr {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestColours(t *testing.T) {
	for name, pair := range map[string][2]string{
		"Red": {Red, "\x1b[0;31m"}, "Green": {Green, "\x1b[0;32m"}, "Yellow": {Yellow, "\x1b[1;33m"},
		"Cyan": {Cyan, "\x1b[0;36m"}, "Bold": {Bold, "\x1b[1m"}, "NC": {NC, "\x1b[0m"},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %q, want %q", name, pair[0], pair[1])
		}
	}
}

// InfoE, WarnE and ErrorE print as 'echo -e' does: escapes interpreted, \c
// ends the output.
func TestEchoHelpers(t *testing.T) {
	var out, errb strings.Builder
	o := Output{Stdout: &out, Stderr: &errb}
	o.InfoE(`a\tb`)
	o.WarnE("plain")
	o.ErrorE(`x\cy`)
	if out.String() != Green+"[INFO]"+NC+" a\tb\n"+Yellow+"[WARN]"+NC+" plain\n" || errb.String() != Red+"[ERROR]"+NC+" x" {
		t.Errorf("stdout %q stderr %q", out.String(), errb.String())
	}
}
