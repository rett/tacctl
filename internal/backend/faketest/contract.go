package faketest

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/rett/tacctl/internal/backend"
)

var idRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// CheckContract is the contract test of tests/unit/backend.bats for one
// backend, made by its module in a test environment: what the Go type
// system does not already check (every verb exists, no stray verbs:
// compile-time now). A module's tests call it on their backend.
//
//   - its id is a valid, unreserved registry id, and Describe names a
//     protocol;
//   - every artifact is an absolute path, none twice;
//   - a lifecycle phase it does not know is a no-op, not an error;
//   - a status part, log or accounting sub-command or service action it
//     does not have is backend.ErrUnsupported (exit 2), and writes nothing.
func CheckContract(t testing.TB, b backend.Backend) {
	t.Helper()
	ctx := context.Background()
	id := b.ID()
	if !idRE.MatchString(id) || backend.IsReserved(id) {
		t.Errorf("contract: id %q is not a valid registry id", id)
	}
	if b.Describe().Protocol == "" {
		t.Errorf("contract: %s: Describe has no protocol", id)
	}
	seen := map[string]bool{}
	for _, a := range b.Artifacts() {
		if !filepath.IsAbs(a) {
			t.Errorf("contract: %s: artifact %q is not an absolute path", id, a)
		}
		if seen[a] {
			t.Errorf("contract: %s: artifact %q listed twice", id, a)
		}
		seen[a] = true
	}
	const nope = backend.Phase("no-such-phase")
	if err := b.Install(ctx, nope, "/nonexistent"); err != nil {
		t.Errorf("contract: %s: install of an unknown phase: %v", id, err)
	}
	if err := b.Upgrade(ctx, nope, "/nonexistent"); err != nil {
		t.Errorf("contract: %s: upgrade of an unknown phase: %v", id, err)
	}
	if err := b.Uninstall(ctx, nope, false); err != nil {
		t.Errorf("contract: %s: uninstall of an unknown phase: %v", id, err)
	}
	unsupported := func(what string, err error) {
		if !errors.Is(err, backend.ErrUnsupported) || backend.ExitCode(err) != 2 {
			t.Errorf("contract: %s: %s: got %v, want ErrUnsupported", id, what, err)
		}
	}
	var w recorder
	unsupported("status nope", b.Status(ctx, "nope", &w))
	unsupported("log nope", b.Log(ctx, "nope", nil, &w))
	unsupported("accounting nope", b.Accounting(ctx, "nope", nil, &w))
	_, err := b.Service(ctx, "frobnicate", "")
	unsupported("service frobnicate", err)
	if w.n != 0 {
		t.Errorf("contract: %s: an unsupported part or sub-command wrote %d bytes", id, w.n)
	}
}

type recorder struct{ n int }

func (r *recorder) Write(p []byte) (int, error) {
	r.n += len(p)
	return len(p), nil
}

var _ io.Writer = (*recorder)(nil)
