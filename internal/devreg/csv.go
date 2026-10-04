package devreg

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Row is one device of an import and where it came from. A CSV row says
// nothing about the hostname or the legacy-ssh flag, so a merge keeps the
// registered values of those.
type Row struct {
	Line   int
	CSV    bool
	Device Device
}

// ParseImport reads an import file: the registry's own YAML (a mapping with
// 'devices:') or CSV 'name,address[,vendor[,port[,login[,description]]]]'
// (blank lines and '#' lines are skipped, and so is a header that starts
// 'name,address'). Every problem is returned, with its line for CSV.
func ParseImport(data []byte) ([]Row, error) {
	if v, err := pyyaml.LoadBytes(data); err == nil {
		if m, ok := v.(*yamlpy.Map); ok {
			if _, has := m.Get("devices"); has {
				f, err := parse(data)
				if err != nil {
					return nil, fail("import: " + strings.Join(msgs(err), " "))
				}
				var rows []Row
				for _, d := range f.Devices {
					rows = append(rows, Row{Device: d.Clone()})
				}
				return rows, nil
			}
		}
	}
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1
	r.Comment = '#'
	r.TrimLeadingSpace = true
	var rows []Row
	var errs []string
	for {
		rec, err := r.Read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			errs = append(errs, "import: "+err.Error())
			break
		}
		line, _ := r.FieldPos(0)
		for i := range rec {
			rec[i] = strings.TrimSpace(rec[i])
		}
		if len(rows) == 0 && len(errs) == 0 && len(rec) >= 2 && strings.EqualFold(rec[0], "name") && strings.EqualFold(rec[1], "address") {
			continue
		}
		if len(rec) < 2 || len(rec) > 6 {
			errs = append(errs, fmt.Sprintf("line %d: expected name,address[,vendor[,port[,login[,description]]]]", line))
			continue
		}
		d := Device{Name: rec[0], Address: rec[1], Vendor: VendorOther}
		field := func(i int) string {
			if i < len(rec) {
				return rec[i]
			}
			return ""
		}
		var rowErrs []error
		if a, err := NormalizeAddress(d.Address); err != nil {
			rowErrs = append(rowErrs, err)
		} else {
			d.Address = a
		}
		if v := field(2); v != "" {
			d.Vendor = strings.ToLower(v)
			rowErrs = append(rowErrs, ValidateVendor(d.Vendor))
		}
		if p := field(3); p != "" {
			n, err := ValidatePort(p)
			rowErrs = append(rowErrs, err)
			d.Port = n
		}
		if l := field(4); l != "" {
			rowErrs = append(rowErrs, ValidateLogin(l))
			d.Login = l
		}
		d.Description = field(5)
		rowErrs = append(rowErrs, ValidateDescription(d.Description), ValidateName(d.Name))
		bad := false
		for _, e := range rowErrs {
			if e != nil {
				bad = true
				errs = append(errs, fmt.Sprintf("line %d: %s", line, strings.Join(msgs(e), " ")))
			}
		}
		if !bad {
			rows = append(rows, Row{Line: line, CSV: true, Device: d})
		}
	}
	if len(errs) > 0 {
		return nil, fail(errs...)
	}
	if len(rows) == 0 {
		return nil, fail("import: no devices found.")
	}
	return rows, nil
}

// ImportResult is what an import did (or, for a check, would do).
type ImportResult struct {
	Added, Updated, Unchanged, Removed []string
}

// Import applies rows to f: devices of the file are added, or update the
// registered device of the same name; with replace the devices the rows do
// not name are removed. Every problem is returned at once and f is left as
// it was. hostEntries are the enrolled hosts (the shared namespace); the rows'
// names are held to the generic list unless allowGeneric.
func (f *File) Import(rows []Row, replace, allowGeneric bool, hostEntries []Entry) (ImportResult, error) {
	var res ImportResult
	var errs []string
	say := func(row Row, msg string) {
		if row.Line > 0 {
			errs = append(errs, fmt.Sprintf("line %d: %s", row.Line, msg))
		} else {
			errs = append(errs, "'"+row.Device.Name+"': "+msg)
		}
	}
	hostNames := map[string]Entry{}
	hostAddrs := map[string]Entry{}
	for _, h := range hostEntries {
		if h.Source == SourceHost {
			hostNames[strings.ToLower(h.Name)] = h
			if h.Address != "" {
				hostAddrs[h.Address] = h
			}
		}
	}
	next := f.Clone()
	inFile := map[string]bool{}
	for _, row := range rows {
		d := row.Device
		lc := strings.ToLower(d.Name)
		if inFile[lc] {
			say(row, "'"+d.Name+"' appears twice in the file.")
			continue
		}
		inFile[lc] = true
		if err := d.validate(); err != nil {
			say(row, strings.Join(msgs(err), " "))
			continue
		}
		if h, ok := hostNames[lc]; ok {
			say(row, "'"+d.Name+"' is an enrolled host ("+h.Name+").")
			continue
		}
		old := next.Find(d.Name)
		if old == nil && !allowGeneric && IsGeneric(d.Name, next.GenericNames) {
			say(row, "'"+d.Name+"' is a generic name; rename the device in the file, or import with --allow-generic.")
			continue
		}
		if old == nil {
			nd := d.Clone()
			next.Devices = append(next.Devices, &nd)
			res.Added = append(res.Added, d.Name)
			continue
		}
		merged := d.Clone()
		if row.CSV {
			merged.Hostname, merged.LegacySSH = old.Hostname, old.LegacySSH
		}
		merged.Name = old.Name
		if len(merged.Ack) == 0 {
			merged.Ack = slices.Clone(old.Ack)
		}
		// An import never changes a pin: a device keeps its pinned keys while
		// its address stays (only 'device hostkey accept|set' re-pins), and
		// pins from the file only where none was.
		if merged.Address == old.Address && len(old.HostKeys) > 0 {
			merged.HostKeys = slices.Clone(old.HostKeys)
		}
		if reflect.DeepEqual(merged, *old) {
			res.Unchanged = append(res.Unchanged, old.Name)
			continue
		}
		*old = merged
		res.Updated = append(res.Updated, old.Name)
	}
	if replace {
		var keep []*Device
		for _, d := range next.Devices {
			if inFile[strings.ToLower(d.Name)] {
				keep = append(keep, d)
			} else {
				res.Removed = append(res.Removed, d.Name)
			}
		}
		next.Devices = keep
	}
	if len(errs) == 0 {
		// Addresses must be unique in the end, among the devices and the hosts.
		seen := map[string]string{}
		for _, d := range next.Devices {
			if other, dup := seen[d.Address]; dup {
				errs = append(errs, d.Address+" would be registered as both '"+other+"' and '"+d.Name+"'.")
			}
			seen[d.Address] = d.Name
			if h, ok := hostAddrs[d.Address]; ok {
				errs = append(errs, d.Address+" ('"+d.Name+"') belongs to the enrolled host '"+h.Name+"'.")
			}
		}
	}
	if len(errs) > 0 {
		return ImportResult{}, fail(errs...)
	}
	*f = *next
	return res, nil
}

// --- export ---------------------------------------------------------------------

// CSV is the devices as CSV with a header row, in the import's columns.
func CSV(devs []Device) []byte {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write([]string{"name", "address", "vendor", "port", "login", "description"})
	for _, d := range devs {
		port := ""
		if d.Port != 0 {
			port = strconv.Itoa(d.Port)
		}
		_ = w.Write([]string{d.Name, d.Address, d.Vendor, port, d.Login, d.Description})
	}
	w.Flush()
	return b.Bytes()
}

// jsonDevice is the JSON form of a device.
type jsonDevice struct {
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	Hostname    string   `json:"hostname,omitempty"`
	Vendor      string   `json:"vendor"`
	Port        int      `json:"port"`
	Login       string   `json:"login,omitempty"`
	LegacySSH   bool     `json:"legacy_ssh"`
	Description string   `json:"description,omitempty"`
	HostKeys    []string `json:"host_keys,omitempty"`
	Ack         []string `json:"ack,omitempty"`
}

// JSONDevice is d as the value 'export --json' and 'list --json' print.
func JSONDevice(d Device) any {
	return jsonDevice{Name: d.Name, Address: d.Address, Hostname: d.Hostname, Vendor: d.Vendor, Port: d.SSHPort(),
		Login: d.Login, LegacySSH: d.LegacySSH, Description: d.Description, HostKeys: d.HostKeys, Ack: d.Ack}
}

// JSON is the devices as an indented JSON array.
func JSON(devs []Device) ([]byte, error) {
	out := make([]any, 0, len(devs))
	for _, d := range devs {
		out = append(out, JSONDevice(d))
	}
	b, err := json.MarshalIndent(out, "", "  ")
	return append(b, '\n'), err
}
