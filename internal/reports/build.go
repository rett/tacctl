package reports

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The report types.
const (
	TypeInventory = "inventory"
	TypeMembers   = "members"
	TypeSoftware  = "software"
	TypeConfig    = "config"
)

// Types lists the report types in the order the documentation names them.
func Types() []string {
	return []string{TypeInventory, TypeMembers, TypeSoftware, TypeConfig}
}

// DateFormat is the layout of every date in the text and CSV reports (UTC).
const DateFormat = "2006-01-02 15:04"

// Report is a built report: the same rows in two shapes, the cells of the
// text and CSV formats and the objects of the JSON format.
type Report struct {
	Schema    int
	Type      string
	Generated time.Time
	Columns   []string
	// Rows holds the cells, raw: an empty cell is "" (only the text renderer
	// shows it as "-"). Each row has len(Columns) cells.
	Rows [][]string
	// Keys is the order of the keys of an object; Objects holds the rows of
	// the JSON format, one object per row, with the same order as Rows.
	Keys    []string
	Objects []map[string]any
	// Devices is the number of devices the report was built from, including
	// those the report leaves out.
	Devices int
	// OldestData is the oldest non-zero Pulled among the devices; zero when no
	// device was ever pulled.
	OldestData time.Time
}

// Columns returns the column names of a report type, or nil for an unknown
// type.
func Columns(typ string) []string {
	switch typ {
	case TypeInventory:
		return []string{"name", "address", "vendor", "scope", "model", "serial", "release", "members", "location", "description", "pulled"}
	case TypeMembers:
		return []string{"device", "member", "role", "model", "serial", "release", "status", "priority", "pulled"}
	case TypeSoftware:
		return []string{"name", "vendor", "model", "release", "gate", "pulled"}
	case TypeConfig:
		return []string{"name", "scope", "state", "pulled", "applied"}
	}
	return nil
}

// jsonKeys is the order of the keys of a JSON row. For the members report the
// row is the member object (id, role, ...) plus the device and the date.
func jsonKeys(typ string) []string {
	switch typ {
	case TypeInventory:
		return []string{"name", "address", "vendor", "scope", "model", "serial", "release", "members", "location", "description", "pulled"}
	case TypeMembers:
		return []string{"device", "id", "role", "model", "serial", "release", "status", "priority", "components", "pulled"}
	case TypeSoftware:
		return []string{"name", "vendor", "model", "release", "gate", "pulled"}
	case TypeConfig:
		return []string{"name", "scope", "state", "pulled", "applied"}
	}
	return nil
}

// Build makes the report of a type from the devices. It does not change devs.
func Build(typ string, devs []Device, now time.Time) (Report, error) {
	cols := Columns(typ)
	if cols == nil {
		return Report{}, fmt.Errorf("unknown report type %q (valid types: %s)", typ, strings.Join(Types(), ", "))
	}
	sorted := make([]Device, len(devs))
	copy(sorted, devs)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	r := Report{
		Schema:    Schema,
		Type:      typ,
		Generated: now.UTC(),
		Columns:   cols,
		Keys:      jsonKeys(typ),
		Devices:   len(devs),
	}
	for _, d := range devs {
		if !d.Pulled.IsZero() && (r.OldestData.IsZero() || d.Pulled.Before(r.OldestData)) {
			r.OldestData = d.Pulled.UTC()
		}
	}
	for _, d := range sorted {
		switch typ {
		case TypeInventory:
			r.add(inventoryRow(d))
		case TypeMembers:
			for _, m := range memberRows(d) {
				r.add(m.cells, m.obj)
			}
		case TypeSoftware:
			r.add([]string{d.Name, d.Vendor, d.Model, d.Release, d.GateState, pulledCell(d.Pulled)},
				map[string]any{"name": d.Name, "vendor": d.Vendor, "model": d.Model, "release": d.Release,
					"gate": d.GateState, "pulled": jsonTime(d.Pulled)})
		case TypeConfig:
			r.add([]string{d.Name, d.Scope, d.ConfigState, pulledCell(d.Pulled), appliedCell(d.Applied)},
				map[string]any{"name": d.Name, "scope": d.Scope, "state": d.ConfigState,
					"pulled": jsonTime(d.Pulled), "applied": jsonTime(d.Applied)})
		}
	}
	return r, nil
}

func (r *Report) add(cells []string, obj map[string]any) {
	r.Rows = append(r.Rows, cells)
	r.Objects = append(r.Objects, obj)
}

func pulledCell(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(DateFormat)
}

func appliedCell(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(DateFormat)
}

// jsonTime is the value of a date in a JSON row: RFC 3339 UTC, null when zero.
func jsonTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func inventoryRow(d Device) ([]string, map[string]any) {
	count := "-"
	if len(d.Members) > 0 {
		count = strconv.Itoa(len(d.Members))
	}
	cells := []string{d.Name, d.Address, d.Vendor, d.Scope, d.Model, d.Serial, d.Release, count,
		d.Location, d.Description, pulledCell(d.Pulled)}
	return cells, map[string]any{
		"name": d.Name, "address": d.Address, "vendor": d.Vendor, "scope": d.Scope,
		"model": d.Model, "serial": d.Serial, "release": d.Release, "members": len(d.Members),
		"location": d.Location, "description": d.Description, "pulled": jsonTime(d.Pulled),
	}
}

type memberRow struct {
	cells []string
	obj   map[string]any
}

// memberRows is the rows of one device in the members report: one per member,
// one for a standalone device with a model or a serial, none for a device with
// neither.
func memberRows(d Device) []memberRow {
	if len(d.Members) == 0 {
		if d.Model == "" && d.Serial == "" {
			return nil
		}
		return []memberRow{{
			cells: []string{d.Name, "-", "-", d.Model, d.Serial, d.Release, "", "", pulledCell(d.Pulled)},
			obj: map[string]any{
				"device": d.Name, "id": "-", "role": "-", "model": d.Model, "serial": d.Serial,
				"release": d.Release, "status": "", "priority": 0, "components": []Component{},
				"pulled": jsonTime(d.Pulled),
			},
		}}
	}
	ms := make([]Member, len(d.Members))
	copy(ms, d.Members)
	sort.SliceStable(ms, func(i, j int) bool { return idLess(ms[i].ID, ms[j].ID) })
	rows := make([]memberRow, 0, len(ms))
	for _, m := range ms {
		comps := m.Components
		if comps == nil {
			comps = []Component{}
		}
		rows = append(rows, memberRow{
			cells: []string{d.Name, m.ID, m.Role, m.Model, m.Serial, m.Release, m.Status,
				strconv.Itoa(m.Priority), pulledCell(d.Pulled)},
			obj: map[string]any{
				"device": d.Name, "id": m.ID, "role": m.Role, "model": m.Model, "serial": m.Serial,
				"release": m.Release, "status": m.Status, "priority": m.Priority, "components": comps,
				"pulled": jsonTime(d.Pulled),
			},
		})
	}
	return rows
}

// idLess orders member ids: numbers first, by value, then anything else by
// bytes. It does not depend on the locale.
func idLess(a, b string) bool {
	an, aerr := strconv.Atoi(a)
	bn, berr := strconv.Atoi(b)
	switch {
	case aerr == nil && berr == nil:
		if an != bn {
			return an < bn
		}
		return a < b
	case aerr == nil:
		return true
	case berr == nil:
		return false
	}
	return a < b
}
