package tacacs

import (
	"context"

	"github.com/rett/tacctl/internal/backend"
)

// The lifecycle phases are WP3.3b's (lifecycle*.go in this package). Until
// that package lands every phase is a no-op, which is what the contract
// asks of a phase a module has no work in. WP3.3b deletes this file when it
// adds its own Install, Upgrade and Uninstall.

// Install is backend_tacacs_install (pending WP3.3b).
func (b *Backend) Install(context.Context, backend.Phase, string) error { return nil }

// Upgrade is backend_tacacs_upgrade (pending WP3.3b).
func (b *Backend) Upgrade(context.Context, backend.Phase, string) error { return nil }

// Uninstall is backend_tacacs_uninstall (pending WP3.3b).
func (b *Backend) Uninstall(context.Context, backend.Phase, bool) error { return nil }
