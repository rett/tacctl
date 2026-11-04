package tacacs

// The accounting log as 'tacctl log accounting' shows it. tacquito's local
// accounter writes one line per request: the logger's prefix (date, time,
// source file and line), then the request as one JSON object
//
//	{"Flags":4,"Method":6,...,"RemAddr":"192.0.2.50","Args":[...],"Device":"192.0.2.10"}
//
// "RemAddr" is where the user connected from, as the device reports it;
// "Device" (patches/0006) is the address of the device that sent the
// record, as the server saw the connection. A record written before the
// patch has no "Device", and is shown without one.
//
// The display is the same line with the object decoded and written again, in
// the order it has on disk: the values as they are (a record written before
// the patch has "<", ">" and "&" as \u003c, \u003e and \u0026, which are
// shown as the characters), "Device" as the registered device's name (the
// address when none is registered), and the "<cr>" Junos appends to a "cmd="
// value left out. The log itself is not changed. A line that is not such a
// record is shown as it is.

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/rett/tacctl/internal/backend"
)

// acctRecordMark starts the object of a record: the first field is "Flags".
const acctRecordMark = `{"Flags":`

// junosCR is what Junos appends to the command of a record.
const junosCR = "<cr>"

// AcctDisplay is line (without its newline) as 'log accounting' shows it;
// name gives the registered device at an address ("" when none, nil: no
// names).
func AcctDisplay(line string, name func(address string) string) string {
	i := strings.Index(line, acctRecordMark)
	if i < 0 {
		return line
	}
	obj, ok := displayRecord(line[i:], name)
	if !ok {
		return line
	}
	return line[:i] + obj
}

// displayRecord is the JSON object at the start of s, rewritten; false when
// s is not one object (and nothing else but white space).
func displayRecord(s string, name func(string) string) (string, bool) {
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", false
	}
	var out strings.Builder
	out.WriteByte('{')
	for n := 0; dec.More(); n++ {
		t, err := dec.Token()
		key, isKey := t.(string)
		if err != nil || !isKey {
			return "", false
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil {
			return "", false
		}
		val, ok := displayValue(key, raw, name)
		if !ok {
			return "", false
		}
		if n > 0 {
			out.WriteByte(',')
		}
		out.WriteString(jsonText(key))
		out.WriteByte(':')
		out.WriteString(val)
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return "", false
	}
	if strings.TrimSpace(s[dec.InputOffset():]) != "" {
		return "", false
	}
	out.WriteByte('}')
	return out.String(), true
}

// displayValue is the value of one field as it is shown.
func displayValue(key string, raw json.RawMessage, name func(string) string) (string, bool) {
	switch key {
	case "Device":
		var dev string
		if json.Unmarshal(raw, &dev) == nil {
			return jsonText(deviceLabel(dev, name)), true
		}
	case "Args":
		var args []string
		if json.Unmarshal(raw, &args) == nil && args != nil {
			for i, a := range args {
				if v, ok := strings.CutPrefix(a, "cmd="); ok {
					args[i] = "cmd=" + strings.TrimRight(strings.TrimSuffix(v, junosCR), " ")
				}
			}
			return jsonText(args), true
		}
	}
	var v any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&v) != nil {
		return "", false
	}
	return jsonText(v), true
}

// deviceLabel is the name of the device at addr, else addr as it is.
func deviceLabel(addr string, name func(string) string) string {
	if name == nil {
		return addr
	}
	if a := backend.CanonAddr(addr); a != "" {
		if n := name(a); n != "" {
			return n
		}
	}
	return addr
}

// jsonText is v as JSON with "<", ">" and "&" as they are. Control
// characters stay escaped, so a value a device chose cannot move the cursor
// or end the line.
func jsonText(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return "null"
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// displayAcct is the lines of tail output shown with AcctDisplay, each
// line's newline (or its absence at the end) kept.
func (b *Backend) displayAcct(data []byte) []byte {
	var out bytes.Buffer
	for len(data) > 0 {
		line, rest, nl := bytes.Cut(data, []byte("\n"))
		out.WriteString(AcctDisplay(string(line), b.env.DeviceName))
		if nl {
			out.WriteByte('\n')
		}
		data = rest
	}
	return out.Bytes()
}
