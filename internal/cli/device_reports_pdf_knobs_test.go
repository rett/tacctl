//go:build testknobs

package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The tool a test build's knob names is the test's own: the rule about its
// owner and the directories above it does not apply to it.
func TestReportsPDFToolKnobIsNotHeldToTheOwnerRule(t *testing.T) {
	b := newReportsBox(t)
	tool := filepath.Join(t.TempDir(), "weasyprint-stub")
	if err := os.WriteFile(tool, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	b.sb.hooks.pdfStat = func(string) (uint32, fs.FileMode, error) { return 1000, 0o777, nil }
	out := b.asWith(pdfStub(tool), []string{"TACCTL_TEST_PDF_TOOL=" + tool}, "alice", asSuper, "generate", "--type", "inventory", "--format", "pdf", "--stdout")
	if b.sb.code != 0 || !strings.HasPrefix(out, "%PDF-1.7\n") || len(toolCalls(b.sb.runner, tool)) != 1 {
		t.Errorf("exit %d %.60q %q", b.sb.code, out, b.sb.stderr())
	}
}
