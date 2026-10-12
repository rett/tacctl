package cli

// What 'config validate' says of the configuration blocks (0.2.7): the
// findings of the store against tacctl.yaml (a name with no file is an
// error: the block renders nothing; a file no list names is a warning: it
// is ignored; a device's orphans are warnings) and a block in force that
// does not parse, which refuses every Junos device it reaches. Nothing
// printed holds a word of a block.

import (
	"slices"
	"sort"
	"strconv"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/policy"
)

// blockValidation are the errors and warnings of the blocks, as one line
// each. A caller the scope filter restricts sees the scopes of their own,
// and no device's.
func (inv *invocation) blockValidation() (errs, warns []string) {
	cfg, st := inv.app.Conf(), inv.deviceBlockStore()
	f := inv.callerScopes()
	add := func(f blocks.StoreFinding) {
		if f.Kind == blocks.KindMissing {
			errs = append(errs, f.Text)
		} else {
			warns = append(warns, f.Text)
		}
	}
	manifest := policy.BlockManifest(cfg)
	fs, err := st.VerifyScopes(manifest)
	if err != nil {
		errs = append(errs, err.Error())
	}
	for _, x := range fs {
		if f.allows(x.Level.Scope) {
			add(x)
		}
	}
	lint := func(l blocks.Level, listed []string, check string) {
		for _, b := range listed {
			text, err := st.Read(l, blocks.VendorJuniper, b)
			if err != nil {
				continue // missing is a finding above, unreadable one of Verify's
			}
			layer := blocks.LayerScope
			if l.IsDevice() {
				layer = blocks.LayerDevice
			}
			if _, fs, err := blocks.LintBlock(b, string(text), layer); err == nil && blocks.HasErrors(fs) {
				n := 0
				for _, x := range fs {
					if x.Severity == blocks.SevError {
						n++
					}
				}
				errs = append(errs, "the "+b+" block of "+l.String()+" has "+strconv.Itoa(n)+" "+plural(n, "error", "errors")+
					" and is not rendered, so every Junos device it reaches is refused: "+check+" "+b)
			}
		}
	}
	var scopes []string
	for sc := range manifest {
		scopes = append(scopes, sc)
	}
	sort.Strings(scopes)
	for _, sc := range scopes {
		if f.allows(sc) {
			lint(blocks.ScopeLevel(sc), manifest[sc][blocks.VendorJuniper], "tacctl scope block "+sc+" juniper check")
		}
	}
	if f.restricted {
		return errs, warns
	}
	devManifest := policy.DeviceBlockManifest(cfg)
	vendorOf := func(device string) (string, bool) {
		file, err := devreg.Load(inv.app.Paths.DevicesFile)
		if err != nil {
			return "", false
		}
		d := file.Find(device)
		if d == nil {
			return "", false
		}
		return d.Vendor, true
	}
	dfs, err := st.VerifyDevices(devManifest, vendorOf)
	if err != nil {
		errs = append(errs, err.Error())
	}
	for _, x := range dfs {
		add(x)
	}
	var devs []string
	for d := range devManifest {
		devs = append(devs, d)
	}
	slices.Sort(devs)
	for _, d := range devs {
		if v, ok := vendorOf(d); ok && v == blocks.VendorJuniper {
			lint(blocks.DeviceLevel(d), devManifest[d][blocks.VendorJuniper], "tacctl device block "+d+" check")
		}
	}
	return errs, warns
}

// blocksExist reports whether there is anything to say about blocks: a list
// in tacctl.yaml or a directory of files.
func (inv *invocation) blocksExist() bool {
	cfg, st := inv.app.Conf(), inv.deviceBlockStore()
	if len(policy.BlockManifest(cfg)) > 0 || len(policy.DeviceBlockManifest(cfg)) > 0 {
		return true
	}
	scopes, _ := st.Scopes()
	devs, _ := st.Devices()
	return len(scopes)+len(devs) > 0
}
