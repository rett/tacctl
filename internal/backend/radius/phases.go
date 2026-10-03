package radius

import (
	"context"
	"fmt"

	"github.com/rett/tacctl/internal/backend"
)

// The lifecycle phases of the contract (backend_radius_install, _upgrade and
// _uninstall) are WP3.3c's: it adds lifecycle.go with the phase bodies and
// deletes this file. Until then a phase of the lifecycle is reported as not
// implemented rather than claimed done; a phase the module does not know is
// a no-op, as the contract says.

var knownPhases = map[string][]backend.Phase{
	"install":   {backend.PhaseBuild, backend.PhaseFiles, backend.PhaseAccount, backend.PhaseStart},
	"upgrade":   {backend.PhaseConfig, backend.PhaseFiles, backend.PhaseFinish},
	"uninstall": {backend.PhaseStop, backend.PhaseData},
}

func pending(verb string, phase backend.Phase) error {
	for _, p := range knownPhases[verb] {
		if p == phase {
			return fmt.Errorf("radius: %s phase %q is not implemented yet (WP3.3c)", verb, phase)
		}
	}
	return nil
}

// Install runs one install phase.
func (m *Module) Install(_ context.Context, phase backend.Phase, _ string) error {
	return pending("install", phase)
}

// Upgrade runs one upgrade phase.
func (m *Module) Upgrade(_ context.Context, phase backend.Phase, _ string) error {
	return pending("upgrade", phase)
}

// Uninstall runs one uninstall phase.
func (m *Module) Uninstall(_ context.Context, phase backend.Phase, _ bool) error {
	return pending("uninstall", phase)
}
