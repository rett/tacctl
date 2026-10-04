package model

import (
	"io"
	"os"

	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// LegacyLoad is the legacy loader of model_load ('dump-legacy', lib/model.sh
// at 0.1.16): the model of the tacquito.yaml at path, canonicalised, as a
// store (not validated: legacy read-only mode serves a file with content
// the store cannot represent), and its typed model. datesDir and
// disabledDir hold the password-date and disabled-hash sidecars ("" for
// none). The loader's report is store.LegacyLoad's.
func LegacyLoad(path, datesDir, disabledDir string) (*store.Store, *Model, error) {
	s, _, err := store.LegacyLoad(path, datesDir, disabledDir)
	if err != nil {
		return nil, nil, err
	}
	return s, FromStore(s), nil
}

// Paths are what model_load reads: the store, the legacy config and the
// legacy loader's sidecar directories.
type Paths struct {
	Store       string // STORE_FILE
	Config      string // CONFIG, the live tacquito.yaml
	DatesDir    string // PASSWORD_DATES_DIR
	DisabledDir string // ${BACKUP_DIR}/disabled
}

// NoSourceError is model_load's failure when neither file exists; 0.1.16
// prints it as '[ERROR] <message>'.
type NoSourceError struct{ Store, Config string }

func (e *NoSourceError) Error() string {
	return "No store at " + e.Store + " and no config at " + e.Config + "."
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// Load is model_load: the store when store.yaml exists (mode "store"),
// else the model of tacquito.yaml (mode "legacy", read-only), else a
// *NoSourceError. Errors from either loader are *store.Error (printed with
// store.Report).
func Load(p Paths) (s *store.Store, m *Model, mode string, err error) {
	switch {
	case isFile(p.Store):
		s, m, err = LoadStore(p.Store)
		return s, m, "store", err
	case isFile(p.Config):
		s, m, err = LegacyLoad(p.Config, p.DatesDir, p.DisabledDir)
		return s, m, "legacy", err
	}
	return nil, nil, "", &NoSourceError{Store: p.Store, Config: p.Config}
}

// Show is cmd_store_show after its argument check ('tacctl store show
// [--json]'): the model as YAML (or JSON) on out.Stdout, after a warning
// on out.Stderr in legacy mode. A load error is returned unprinted
// (*NoSourceError: '[ERROR] <message>'; anything else: store.Report).
func Show(out ui.Output, p Paths, asJSON bool) error {
	s, _, mode, err := Load(p)
	if err != nil {
		return err
	}
	if mode == "legacy" {
		ui.Output{Stdout: out.Stderr}.Warn("No store yet — showing the model derived from " + p.Config + " (legacy read-only mode).")
	}
	var text string
	if asJSON {
		text, err = ShowJSON(s)
	} else {
		var b []byte
		b, err = ShowYAML(s)
		text = string(b)
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(out.Stdout, text)
	return err
}
