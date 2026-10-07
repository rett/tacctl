package conf

import "github.com/rett/tacctl/internal/yamlpy"

// View is a read-only Config over a merged view that was read elsewhere
// (the renderers get the view, not the file), so the readers that take a
// *Config (Get, GetList, the policy package) work on it too. Nothing may
// be written through it.
func View(merged *yamlpy.Map) *Config {
	if merged == nil {
		merged = yamlpy.NewMap()
	}
	return &Config{merged: merged}
}
