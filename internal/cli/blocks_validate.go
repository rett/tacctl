package cli

// What 'config validate' says of the configuration blocks (0.2.7): the
// findings of the store against tacctl.yaml (a name with no file is an
// error: the block renders nothing; a file no list names is a warning: it
// is ignored; a device's orphans are warnings) and a block in force that
// does not parse, which refuses every device of its vendor it reaches. Nothing
// printed holds a word of a block.

import (
	"slices"
	"sort"
	"strconv"
	"strings"

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
	lint := func(l blocks.Level, vendor string, listed []string, check string) {
		who := "Junos"
		if vendor == blocks.VendorCisco {
			who = "IOS"
		}
		for _, b := range listed {
			text, err := st.Read(l, vendor, b)
			if err != nil {
				continue // missing is a finding above, unreadable one of Verify's
			}
			layer := blocks.LayerScope
			if l.IsDevice() {
				layer = blocks.LayerDevice
			}
			_, fs, err := blocks.LintFor(vendor, b, string(text), layer)
			if err != nil {
				// a name that has no grammar for the vendor: it is never
				// rendered
				errs = append(errs, "the "+b+" block of "+l.String()+" ("+vendor+") is not built for "+who+" and is not rendered: "+strings.Join(msgs(err), " "))
				continue
			}
			if blocks.HasErrors(fs) {
				n := 0
				for _, x := range fs {
					if x.Severity == blocks.SevError {
						n++
					}
				}
				errs = append(errs, "the "+b+" block of "+l.String()+" has "+strconv.Itoa(n)+" "+plural(n, "error", "errors")+
					" and is not rendered, so every "+who+" device it reaches is refused: "+check+" "+b)
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
			for _, v := range blocks.Vendors {
				lint(blocks.ScopeLevel(sc), v, manifest[sc][v], "tacctl scope block "+sc+" "+v+" check")
			}
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
		if v, ok := vendorOf(d); ok && slices.Contains(blocks.Vendors, v) {
			lint(blocks.DeviceLevel(d), v, devManifest[d][v], "tacctl device block "+d+" check")
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
