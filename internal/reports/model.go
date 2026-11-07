// Package reports builds and renders the device reports of tacctl (inventory,
// members, software, config): the model, the row builders, the text, CSV and
// JSON renderers, the metadata file kept next to a report, and the rules for
// names and limits (docs/plans/0.2.26-plan.md, D316 to D326).
//
// The package imports the standard library only. The CLI adapts the stored
// device records into Device values and does the file handling.
package reports

import (
	"encoding/json"
	"time"
)

// Schema is the schema number of the JSON report and of the metadata file.
const Schema = 1

// Component is a part of a chassis member (power supply, fan, line card,
// optic). It is reserved: 0.2.26 never fills it, and a member always carries
// the empty list in a JSON report so that 0.2.27 changes rows, not the format.
type Component struct {
	Kind   string `json:"kind"`
	Slot   string `json:"slot"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
	Status string `json:"status"`
}

// Member is one member of a chassis (a virtual chassis or a stack).
type Member struct {
	ID         string      `json:"id"`
	Role       string      `json:"role"`
	Model      string      `json:"model"`
	Serial     string      `json:"serial"`
	Release    string      `json:"release"`
	Status     string      `json:"status"`
	Priority   int         `json:"priority"`
	Components []Component `json:"components"`
}

// MarshalJSON writes the components as [] when there are none, never null.
func (m Member) MarshalJSON() ([]byte, error) {
	type plain Member
	p := plain(m)
	if p.Components == nil {
		p.Components = []Component{}
	}
	return json.Marshal(p)
}

// Device is what a report needs of one device. Text fields are as the record
// keeps them (the caller has already cleaned them).
type Device struct {
	Name        string `json:"name"`
	Address     string `json:"address"`
	Vendor      string `json:"vendor"`
	Scope       string `json:"scope"`
	Model       string `json:"model"`
	Serial      string `json:"serial"`
	Release     string `json:"release"`
	Location    string `json:"location"`
	Description string `json:"description"`
	// Pulled is the time of the pull the facts came from; zero means never.
	Pulled time.Time `json:"pulled"`
	// Applied is the time of the last apply; zero means never.
	Applied time.Time `json:"applied"`
	// ConfigState is the state word of `device config list`: ok, differs,
	// never or failed; empty when the caller may not see it (below the
	// operator tier), and the config report then shows "-" (null in JSON).
	ConfigState string   `json:"config_state"`
	Members     []Member `json:"members"`
}

// MarshalJSON writes the members as [] when there are none, never null.
func (d Device) MarshalJSON() ([]byte, error) {
	type plain Device
	p := plain(d)
	if p.Members == nil {
		p.Members = []Member{}
	}
	return json.Marshal(p)
}
