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
func TestShippedModulesAreRegisteredTacacsFirst(t *testing.T) {
	want := []string{backend.TACACS, backend.RADIUS}
	ids := backend.Default().IDs()
	if !slices.Equal(ids, want) {
		t.Fatalf("registered %v, want %v", ids, want)
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
