package radius

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/model"
	rr "github.com/rett/tacctl/internal/render/radius"
)

// notes is _radius_notes: what the rendered state means for an operator
// (render/radius.Notes). Nothing when there is no store or the store or
// tacctl.yaml cannot be read: the callers print what they can.
func (m *Module) notes() []rr.Note {
	if !isFile(m.env.Paths.StoreFile) {
		return nil
	}
	s, err := m.loadStore()
	if err != nil {
		return nil
	}
	merged, err := rr.ConfView(m.env.Conf)
	if err != nil {
		return nil
	}
	return rr.Notes(model.FromStore(s), merged)
}

// RenderNotes is backend_radius_render_notes: the warnings after 'tacctl
// config render' (and 'backend enable'): command rules RADIUS cannot
// enforce, secrets beyond the interoperability advice, and the scopes whose
// network devices would get Service-Type alone.
func (m *Module) RenderNotes(context.Context) {
	out := m.env.Out
	for _, n := range m.notes() {
		switch n.Kind {
		case "commands":
			out.Warn("RADIUS does not enforce the command rules (commands.<group>) of: " + n.Detail + ". Over RADIUS their users are limited only by the group's privilege level (Cisco), login class (Juniper) or access level (WTI), where the scope sends it.")
		case "secret":
			out.Warn("The secret of scope " + n.Detail + " is longer than " + strconv.Itoa(rr.SecretMaxLen) + " characters or has a space or a non-ASCII character: FreeRADIUS takes it, some RADIUS clients do not.")
		}
	}
	// The scopes whose network devices would get Service-Type alone (the
	// same test as 'config validate'; Linux-host scopes need nothing).
	if gaps := m.vendorGaps(); len(gaps) > 0 {
		out.Warn("Over RADIUS no vendor attribute is sent to the devices of scope(s) " + strings.Join(gaps, ", ") +
			": an Access-Accept carries Service-Type only. Enable what they need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti")
	}
}

// vendorGaps is model_vendor_gaps: the scopes RADIUS serves that send no
// vendor attribute and are not Linux-host scopes, by name. It reads the host
// registry for how many hosts enrolled in each scope. Nothing when the model
// cannot be read.
func (m *Module) vendorGaps() []string {
	_, mdl, _, err := model.Load(m.modelPaths())
	if err != nil {
		return nil
	}
	return mdl.VendorGaps(m.hostCounts())
}

// hostCounts is the host registry's scopes counted (field 4 of every line,
// when not empty).
func (m *Module) hostCounts() map[string]int {
	counts := map[string]int{}
	f, err := os.Open(m.env.Paths.LinuxHosts)
	if err != nil {
		return counts
	}
	defer func() { _ = f.Close() }()
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadString('\n')
		if line != "" {
			if fl := strings.Split(strings.TrimSuffix(line, "\n"), "|"); len(fl) >= 4 && fl[3] != "" {
				counts[fl[3]]++
			}
		}
		if err != nil {
			return counts
		}
	}
}
