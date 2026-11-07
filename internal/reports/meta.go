package reports

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Meta is what lies in the .meta file next to a report and what `show` prints.
type Meta struct {
	Schema int
	// Name is the report's name without the extension, Format its format.
	Name   string
	Type   string
	Format string
	// User is the user who generated it, Command the exact command line.
	User    string
	Command string
	Filters map[string]string
	// Generated is when the report was made; OldestData is the oldest pull its
	// rows came from (zero when no device was pulled).
	Generated  time.Time
	OldestData time.Time
	// Size is the size of the report file in bytes, Count the number of rows.
	Size  int64
	Count int
}

// metaWire is the JSON shape of Meta.
type metaWire struct {
	Schema     int               `json:"schema"`
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Format     string            `json:"format"`
	User       string            `json:"user"`
	Command    string            `json:"command"`
	Filters    map[string]string `json:"filters"`
	Generated  time.Time         `json:"generated"`
	OldestData *time.Time        `json:"oldest_data"`
	Size       int64             `json:"size"`
	Count      int               `json:"count"`
}

// MarshalMeta writes the metadata as indented JSON with a final newline. A
// zero Schema is written as the current one; the times are UTC; a zero
// OldestData is null and no Filters is {}.
func MarshalMeta(m Meta) ([]byte, error) {
	if m.Schema == 0 {
		m.Schema = Schema
	}
	if m.Schema != Schema {
		return nil, fmt.Errorf("cannot write report metadata of schema %d (this tacctl writes schema %d)", m.Schema, Schema)
	}
	w := metaWire{
		Schema: m.Schema, Name: m.Name, Type: m.Type, Format: m.Format, User: m.User,
		Command: m.Command, Filters: m.Filters, Generated: m.Generated.UTC(),
		Size: m.Size, Count: m.Count,
	}
	if w.Filters == nil {
		w.Filters = map[string]string{}
	}
	if !m.OldestData.IsZero() {
		t := m.OldestData.UTC()
		w.OldestData = &t
	}
	b, err := marshal(w)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// ParseMeta reads a metadata file. It is strict: a schema number newer than
// this tacctl knows is refused with a message saying so, a missing schema and
// any unknown key of schema 1 are errors, and so is anything after the object.
func ParseMeta(b []byte) (Meta, error) {
	var probe struct {
		Schema *int `json:"schema"`
	}
	if err := json.Unmarshal(b, &probe); err != nil {
		return Meta{}, fmt.Errorf("report metadata: %w", err)
	}
	switch {
	case probe.Schema == nil || *probe.Schema < 1:
		return Meta{}, errors.New("report metadata: no valid schema number")
	case *probe.Schema > Schema:
		return Meta{}, fmt.Errorf("report metadata has schema %d, newer than the %d this tacctl reads (a newer tacctl wrote it)", *probe.Schema, Schema)
	}
	var w metaWire
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return Meta{}, fmt.Errorf("report metadata: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Meta{}, errors.New("report metadata: unexpected data after the object")
	}
	m := Meta{
		Schema: w.Schema, Name: w.Name, Type: w.Type, Format: w.Format, User: w.User,
		Command: w.Command, Filters: w.Filters, Generated: w.Generated.UTC(),
		Size: w.Size, Count: w.Count,
	}
	if m.Filters == nil {
		m.Filters = map[string]string{}
	}
	if w.OldestData != nil {
		m.OldestData = w.OldestData.UTC()
	}
	return m, nil
}
