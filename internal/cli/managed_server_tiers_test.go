package cli

import "testing"

// A lowered tier reaches the accounts of this server at once while it is in
// the managed scope, though no user has the scope in the store.
func TestManagedServerSyncsAfterALoweredTier(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs)
	hs.run(nil, "group", "edit", "operator", "tier", "readonly")
	hs.expect(0, "The tier of 'operator' is lower now: syncing this server's accounts (authsrv).", "")
}
