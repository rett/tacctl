package tacacs

import (
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

// DefaultLoader is the read-back's legacy_load(path) of 0.1.16: the
// importer of 'store import' (store.LegacyRaw, not canonicalised, without
// the password-date and disabled-hash side files) and its errors and
// dropped content. Its refusals are *store.Error, so rendered.Report words
// them as 0.1.16 did.
func DefaultLoader(path string) (*LegacyResult, error) {
	s, rep, err := store.LegacyRaw(path, "", "")
	if err != nil {
		return nil, err
	}
	return &LegacyResult{Model: model.FromStore(s), Errors: rep.Errors, Dropped: rep.Dropped}, nil
}
