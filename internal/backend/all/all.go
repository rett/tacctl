// Package all registers every backend module this tacctl ships with the
// default registry (backend.Default): a program imports it once, for its
// side effect, and the registry then holds tacacs and radius in that order
// whatever order the modules' init functions run in.
package all

import (
	// The TACACS+ module (tacquito).
	_ "github.com/rett/tacctl/internal/backend/tacacs"
	// The RADIUS module (FreeRADIUS).
	_ "github.com/rett/tacctl/internal/backend/radius"
)
