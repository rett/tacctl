package all_test

import (
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	_ "github.com/rett/tacctl/internal/backend/all"
)

// The shipped registry: "contract: tacacs and radius are registered,
// exactly once each, tacacs first" (tests/unit/backend.bats) for the real
// modules (registering twice panics in init, so once each holds by
// construction).
//
// TODO(coordinator): this package imports only the TACACS+ module so far.
// When WP2.3's internal/backend/radius is imported in all.go, replace the
// prefix check below with
//
//	if !slices.Equal(ids, want) { t.Fatalf(...) }
func TestShippedModulesAreRegisteredTacacsFirst(t *testing.T) {
	want := []string{backend.TACACS, backend.RADIUS}
	ids := backend.Default().IDs()
	if len(ids) == 0 || len(ids) > len(want) || !slices.Equal(ids, want[:len(ids)]) {
		t.Fatalf("registered %v, want a prefix of %v starting with tacacs", ids, want)
	}
	for _, id := range ids {
		if !backend.Default().Has(id) {
			t.Fatalf("%s listed but not registered", id)
		}
	}
	if backend.Default().Has(backend.TACACSS) {
		t.Fatal("the reserved id is registered")
	}
}
