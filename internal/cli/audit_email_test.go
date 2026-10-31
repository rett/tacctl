package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// The address of a user is personal data: it is in no audit line (of any
// tag) whichever way it is typed, the right way, the wrong way or in the place
// of another word, and whether the command succeeds or is refused.
const (
	markerEmail  = "marker.7f3a91c2e5d@example.net"
	markerEmail2 = "MARKER.other4b8d60a1f93@example.org"
)

func TestNoEmailReachesTheAuditLog(t *testing.T) {
	sb := newSandbox(t, true)
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	markers := []string{markerEmail, markerEmail2, "7f3a91c2e5d", "4b8d60a1f93"}
	cases := []struct {
		name string
		args []string
		// start is what the start line must end in; "" no check, "-" no start
		// line (a read, or a refusal before the verb wrote anything).
		start string
	}{
		{"set", []string{"user", "email", "bob", markerEmail}, `args="bob <redacted>"`},
		{"set again", []string{"user", "email", "bob", markerEmail}, ""},
		{"set, other case", []string{"user", "email", "bob", strings.ToUpper(markerEmail)}, `args="bob <redacted>"`},
		{"held by another user", []string{"user", "email", "carol", markerEmail}, "-"},
		{"change", []string{"user", "email", "bob", markerEmail2}, `args="bob <redacted>"`},
		{"read", []string{"user", "email", "bob"}, "-"},
		{"clear", []string{"user", "email", "bob", "clear"}, `args="bob clear"`},
		{"clear when none", []string{"user", "email", "bob", "clear"}, ""},
		{"address for the name", []string{"user", "email", markerEmail}, "-"},
		{"address for the name, then another", []string{"user", "email", markerEmail, markerEmail2}, "-"},
		{"address, extra words", []string{"user", "email", "bob", markerEmail, markerEmail2, "x"}, "-"},
		{"unknown user", []string{"user", "email", "nobody", markerEmail}, "-"},
		{"not an address", []string{"user", "email", "bob", "not-" + markerEmail + " x"}, "-"},
		{"clear in the name place", []string{"user", "email", "clear", markerEmail}, "-"},
		{"add --email", []string{"user", "add", "dave", "operator", "--hash", h, "--scopes", "lab", "--email", markerEmail, "--no-change-required"},
			`args="dave operator --hash <redacted> --scopes lab --email <redacted> --no-change-required"`},
		{"add --email=", []string{"user", "add", "erin", "operator", "--hash", h, "--scopes", "lab", "--email=" + markerEmail2, "--no-change-required"}, ""},
		{"add --email, held", []string{"user", "add", "frank", "operator", "--hash", h, "--scopes", "lab", "--email", markerEmail}, ""},
		{"add --email, bad", []string{"user", "add", "gina", "operator", "--hash", h, "--scopes", "lab", "--email", "<" + markerEmail + ">"}, ""},
		{"add positional", []string{"user", "add", "hank", "operator", markerEmail}, `args="hank operator <redacted>"`},
		{"add --email twice", []string{"user", "add", "ivan", "operator", "--hash", h, "--email", markerEmail, "--email", markerEmail2, "--no-change-required"}, ""},
		{"add misspelt flag", []string{"user", "add", "jane", "operator", "--emial", markerEmail}, ""},
	}
	for _, c := range cases {
		sb.cfgRun("", c.args, nil, "SUDO_USER=alice", "SUDO_UID=1001")
		noLoggerHas(t, c.name, sb.runner, markers...)
		start := auditLine(sb.runner, "cmd start ")
		switch {
		case c.start == "":
		case c.start == "-" && start != "":
			t.Errorf("%s: unexpected start line %s", c.name, start)
		case c.start != "-" && !strings.HasSuffix(start, c.start):
			t.Errorf("%s: start line\n got %s\nwant it to end in %s", c.name, start, c.start)
		}
	}
	// an address typed in the place of a name, a group or a scope of another
	// user verb is in no audit line and in no message
	probes := [][]string{
		{"user", "add", "zed", markerEmail},
		{"user", "add", "zed", "operator", "--hash", h, "--scopes", markerEmail},
		{"user", "add", "zed", "operator", "--hash", h, "--scopes", "lab," + markerEmail},
		{"user", "add", markerEmail, "operator"},
		{"user", "add", "zed", "operator", "--hash", h, markerEmail},
		{"user", "remove", markerEmail},
		{"user", "rename", markerEmail, "zed"},
		{"user", "rename", "bob", markerEmail},
		{"user", "disable", markerEmail},
		{"user", "enable", markerEmail},
		{"user", "passwd", markerEmail},
		{"user", "passwd", "bob", markerEmail},
		{"user", "move", markerEmail, "operator"},
		{"user", "move", "bob", markerEmail},
		{"user", "scope", markerEmail, "list"},
		{"user", "scope", "bob", "add", markerEmail},
		{"user", "scope", "bob", "replace", "lab," + markerEmail},
		{"user", "require-password-change", markerEmail},
		{"user", "require-password-change", "bob", markerEmail},
		{"user", "email", "bob", "--email=" + markerEmail},
		{"user", "email", "bob", "--email", markerEmail},
		{"user", "email", markerEmail, "clear"},
	}
	for _, args := range probes {
		sb.cfgRun("", args, nil, "SUDO_USER=alice", "SUDO_UID=1001")
		noLoggerHas(t, strings.Join(args[:2], " ")+" probe", sb.runner, markers...)
		if said := sb.out.String() + sb.err.String(); strings.Contains(said, "7f3a91c2e5d") {
			t.Errorf("%q repeats the address:\n%s", args, said)
		}
	}
	if got := emailOf(t, sb, "bob"); strings.Contains(got, "--email") || strings.Contains(got, "7f3a91c2e5d") {
		t.Errorf("bob's address is %q", got)
	}

	// the end and detail lines say what happened, never to whom
	sb.cfgRun("", []string{"user", "email", "bob", "final.bob@example.net"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	noLoggerHas(t, "final set", sb.runner, "final.bob")
	wantDetail(t, "user email", auditCalls(sb.runner), "auth.info", "user email name=bob op=set by=alice")
	sb.cfgRun("", []string{"user", "email", "bob", "clear"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	wantDetail(t, "user email clear", auditCalls(sb.runner), "auth.info", "user email name=bob op=clear by=alice")
}
