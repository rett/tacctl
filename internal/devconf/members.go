package devconf

// Chassis members: the units of a Junos virtual chassis or a Cisco stack,
// read from the output of a few more read commands (best effort, like the
// other facts). A device with no virtual chassis or stack, or with a single
// member, has none: the readers return nil for it and for a reply that is not
// what the command prints.

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// maxMembers bounds how many members the record keeps.
const maxMembers = 32

// Member is one unit of a chassis. Role is master, backup, linecard or
// member; a role text a vendor prints that is none of these is kept in Status
// after the state. Priority is 0 when the vendor prints none. A field a
// reader could not read is "".
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

// Component is a part of a member (a power supply, a fan, a line card, an
// optic). It is reserved: no reader fills Components yet, so a Member carries
// an empty list (MarshalJSON writes it as [], never null).
type Component struct {
	Kind   string `json:"kind"`
	Slot   string `json:"slot"`
	Model  string `json:"model"`
	Serial string `json:"serial"`
	Status string `json:"status"`
}

// MarshalJSON writes Components as a list even when it is empty.
func (m Member) MarshalJSON() ([]byte, error) {
	type plain Member
	if m.Components == nil {
		m.Components = []Component{}
	}
	return json.Marshal(plain(m))
}

// cleanMembers is ms with each field cleaned as the record keeps it, at most
// maxMembers of them and a negative priority as 0; nil when there are none.
func cleanMembers(ms []Member) []Member {
	if len(ms) == 0 {
		return nil
	}
	ms = ms[:min(len(ms), maxMembers)]
	out := make([]Member, len(ms))
	for i, m := range ms {
		c := Member{ID: cleanFact(m.ID), Role: cleanFact(m.Role), Model: cleanFact(m.Model), Serial: cleanFact(m.Serial),
			Release: cleanFact(m.Release), Status: cleanFact(m.Status), Priority: max(m.Priority, 0)}
		for _, p := range m.Components {
			c.Components = append(c.Components, Component{Kind: cleanFact(p.Kind), Slot: cleanFact(p.Slot),
				Model: cleanFact(p.Model), Serial: cleanFact(p.Serial), Status: cleanFact(p.Status)})
		}
		out[i] = c
	}
	return out
}

var (
	// reJunosVCRow is a row of the member table of 'show virtual-chassis
	// status': '0 (FPC 0)  Prsnt  SN000001  ex4300-48t  129  Master*  N  VC
	// 1  vcp-255/1/0'. The rows under it that list only neighbour interfaces
	// have no '(FPC n)' and do not match.
	reJunosVCRow = regexp.MustCompile(`^(\d+)\s+\([A-Za-z]+\s*\d+\)\s+(\S+)(?:\s+(.*))?$`)
	reDigits     = regexp.MustCompile(`^\d+$`)
	// reJunosFPC is the 'FPC n' row of 'show chassis hardware'.
	reJunosFPC = regexp.MustCompile(`^FPC\s+(\d+)\b`)
	// reJunosLabel is the label line that opens the block of one member in
	// 'show version' ('fpc1:', 're0:', 'localre:').
	reJunosLabel = regexp.MustCompile(`^([a-z]+)(\d*):$`)
)

// junosRole is the role a virtual chassis table prints ('Master*': the star
// marks the member the session is on).
func junosRole(tok string) (string, bool) {
	switch strings.ToLower(strings.TrimRight(tok, "*")) {
	case "master":
		return "master", true
	case "backup":
		return "backup", true
	case "linecard":
		return "linecard", true
	}
	return "", false
}

// joinStatus appends an unknown role text to a state.
func joinStatus(state, role string) string {
	if role == "" {
		return state
	}
	if state == "" {
		return role
	}
	return state + " " + role
}

// junosVCRow reads the member row of the virtual chassis table; ok is false
// for any other line.
func junosVCRow(line string) (m Member, ok bool) {
	g := reJunosVCRow.FindStringSubmatch(strings.TrimSpace(line))
	if g == nil {
		return Member{}, false
	}
	m = Member{ID: g[1], Status: g[2]}
	fields := strings.Fields(g[3])
	roleIdx := -1
	for k, t := range fields {
		if r, isRole := junosRole(t); isRole {
			roleIdx, m.Role = k, r
			break
		}
	}
	var pre []string
	switch {
	case roleIdx >= 0:
		pre = fields[:roleIdx]
	default:
		// The serial number, the model and the priority, then a role text
		// this reader does not know; a member that is not present may print
		// the first two only.
		pre = fields[:min(2, len(fields))]
		for k := 1; k < len(fields); k++ {
			if reDigits.MatchString(fields[k]) {
				pre = fields[:k+1]
				if k+1 < len(fields) {
					m.Status = joinStatus(m.Status, fields[k+1])
				}
				break
			}
		}
	}
	if n := len(pre); n >= 2 && reDigits.MatchString(pre[n-1]) {
		m.Priority, _ = strconv.Atoi(pre[n-1])
		pre = pre[:n-1]
	}
	switch len(pre) {
	case 0:
	case 1:
		// A column the device left empty: a word with a dash or a lower
		// case letter is a model, else the serial number.
		if strings.ContainsAny(pre[0], "-abcdefghijklmnopqrstuvwxyz") {
			m.Model = pre[0]
		} else {
			m.Serial = pre[0]
		}
	default:
		m.Serial, m.Model = pre[0], pre[1]
	}
	return m, true
}

// junosFPCRows is the model (the description column) and the serial number
// of each 'FPC n' row of the output of 'show chassis hardware', by number.
// The columns are cut where the header puts them, else the row is split on
// runs of blanks (as JunosChassis does).
func junosFPCRows(out string) map[string][2]string {
	rows := map[string][2]string{}
	serialAt, descAt := -1, -1
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimRight(l, " ")
		if strings.HasPrefix(l, "Item") && strings.Contains(l, "Description") {
			serialAt, descAt = strings.Index(l, "Serial number"), strings.Index(l, "Description")
			continue
		}
		g := reJunosFPC.FindStringSubmatch(l)
		if g == nil {
			continue
		}
		if _, seen := rows[g[1]]; seen {
			continue
		}
		var model, serial string
		aligned := serialAt > 0 && descAt > serialAt && (len(l) <= serialAt || l[serialAt-1] == ' ') && (len(l) <= descAt || l[descAt-1] == ' ')
		switch {
		case aligned:
			// A column the device left empty ends the row early.
			if len(l) > serialAt {
				serial = strings.TrimSpace(l[serialAt:min(descAt, len(l))])
			}
			if len(l) > descAt {
				model = strings.TrimSpace(l[descAt:])
			}
		default:
			parts := splitBlanks(strings.TrimSpace(strings.TrimPrefix(l, "FPC")))
			if len(parts) >= 3 {
				// 'n', then the version and the part number when printed,
				// the serial number and the description last.
				serial, model = parts[len(parts)-2], parts[len(parts)-1]
			}
		}
		rows[g[1]] = [2]string{model, serial}
	}
	return rows
}

// junosVersionBlocks splits the output of 'show version' into the text before
// its first label and the block of each 'fpcN:' label, by number (the first
// block of a number wins). A label of another kind ('re0:', 'localre:')
// closes the block before it and opens one that is dropped.
func junosVersionBlocks(out string) (pre string, byFPC map[string]string) {
	type block struct {
		fpc  string // "" for the text before the first label and for a label of another kind
		text strings.Builder
	}
	blocks := []*block{{}}
	for _, l := range strings.Split(out, "\n") {
		cur := blocks[len(blocks)-1]
		if g := reJunosLabel.FindStringSubmatch(strings.TrimSpace(l)); g != nil {
			b := &block{}
			if g[1] == "fpc" && g[2] != "" {
				b.fpc = g[2]
			}
			blocks = append(blocks, b)
			continue
		}
		cur.text.WriteString(l)
		cur.text.WriteByte('\n')
	}
	byFPC = map[string]string{}
	for _, b := range blocks[1:] {
		if _, seen := byFPC[b.fpc]; b.fpc != "" && !seen {
			byFPC[b.fpc] = b.text.String()
		}
	}
	return blocks[0].text.String(), byFPC
}

// JunosMembers is the members of the virtual chassis that the output of
// 'show virtual-chassis status' lists (id, role, status, priority, serial
// number and model), with the model and the serial number the 'FPC n' rows of
// 'show chassis hardware' give (they win when not empty) and the release of
// the member's block of 'show version' (the text before the first label is
// the master's when the master has no label of its own; "" for a member with
// no block). nil when the first output has no member table (a refusal, an
// error, an empty reply) or lists fewer than two members: one is no chassis.
func JunosMembers(vcStatus, hardware, version string) []Member {
	var ms []Member
	seen := map[string]bool{}
	for _, l := range strings.Split(vcStatus, "\n") {
		if m, ok := junosVCRow(l); ok && !seen[m.ID] {
			seen[m.ID] = true
			ms = append(ms, m)
		}
	}
	if len(ms) < 2 {
		return nil
	}
	hw := junosFPCRows(hardware)
	pre, blocks := junosVersionBlocks(version)
	masterSeen := false
	for i := range ms {
		m := &ms[i]
		if r, ok := hw[m.ID]; ok {
			if r[0] != "" {
				m.Model = r[0]
			}
			if r[1] != "" {
				m.Serial = r[1]
			}
		}
		text, labelled := blocks[m.ID]
		if !labelled && m.Role == "master" && !masterSeen {
			text = pre
		}
		if m.Role == "master" {
			masterSeen = true
		}
		rel, model := JunosVersion(text)
		m.Release = rel
		if m.Model == "" {
			m.Model = model
		}
	}
	return cleanMembers(ms)
}

var (
	// reIOSSwitchRow is a row of 'show switch': '*1  Master 0000.5e00.5301
	// 15  V01  Ready' (the star marks the local switch). The H/W version
	// column may be blank ('4  Member 0000.0000.0000  1  Provisioned'): the
	// word after the priority is then the state.
	reIOSSwitchRow = regexp.MustCompile(`^\*?\s*(\d+)\s+(\S+)\s+[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\s+(\d+)\s+(?:\S+\s+)?(\S.*)$`)
	reIOSName      = regexp.MustCompile(`(?i)^NAME:\s*"\s*(?:Switch\s+)?(\d+)\s*"`)
	// reIOSVersionHead is the header of the per-switch table of 'show
	// version', 'Switch Ports Model SW Version SW Image'.
	reIOSVersionHead = regexp.MustCompile(`^Switch\s+Ports\s+Model\s+SW Version\b`)
	reIOSVersionRow  = regexp.MustCompile(`^\*?\s*(\d+)\s+\d+\s+(\S+)\s+(\S+)(?:\s|$)`)
)

// IOSMembers is the members of the stack that the output of 'show switch'
// lists (number, role, priority and state), with the model and the serial
// number of each member's chassis entry ('Switch N' or 'N') of 'show
// inventory' and the model and release of its row of the table in 'show
// version' when it prints one. The role Master (IOS 12.x and 15.x) or Active
// (IOS-XE 16.x and later) is master, Member member and Standby backup, the
// words Junos' master and backup use too; any other role text is kept in Status
// after the state. nil
// when the first output lists no switch (a refusal, an empty reply) or fewer
// than two: one is no stack.
func IOSMembers(showSwitch, inventory, version string) []Member {
	var ms []Member
	seen := map[string]bool{}
	for _, l := range strings.Split(showSwitch, "\n") {
		g := reIOSSwitchRow.FindStringSubmatch(strings.TrimSpace(l))
		if g == nil || seen[g[1]] {
			continue
		}
		seen[g[1]] = true
		m := Member{ID: g[1], Status: g[4]}
		m.Priority, _ = strconv.Atoi(g[3])
		switch strings.ToLower(g[2]) {
		case "master", "active":
			// IOS 12.x and 15.x print Master, IOS-XE 16.x and later Active
			m.Role = "master"
		case "member":
			m.Role = "member"
		case "standby":
			m.Role = "backup"
		default:
			m.Status = joinStatus(m.Status, g[2])
		}
		ms = append(ms, m)
	}
	if len(ms) < 2 {
		return nil
	}
	type inv struct{ model, serial string }
	chassis := map[string]inv{}
	name := ""
	for _, l := range strings.Split(inventory, "\n") {
		t := strings.TrimSpace(l)
		if strings.HasPrefix(t, "NAME:") {
			name = ""
			if g := reIOSName.FindStringSubmatch(t); g != nil {
				name = g[1]
			}
			continue
		}
		if name == "" || !strings.HasPrefix(t, "PID:") {
			continue
		}
		if g := reIOSPID.FindStringSubmatch(t); g != nil {
			if _, dup := chassis[name]; !dup {
				chassis[name] = inv{g[1], g[2]}
			}
		}
		name = ""
	}
	type ver struct{ model, release string }
	table := map[string]ver{}
	inTable := false
scan:
	for _, l := range strings.Split(version, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case reIOSVersionHead.MatchString(t):
			inTable = true
		case !inTable || strings.HasPrefix(t, "---"):
		case t == "":
			if len(table) > 0 {
				break scan
			}
		default:
			g := reIOSVersionRow.FindStringSubmatch(t)
			if g == nil {
				break scan
			}
			if _, dup := table[g[1]]; !dup {
				table[g[1]] = ver{g[2], g[3]}
			}
		}
	}
	for i := range ms {
		m := &ms[i]
		if c, ok := chassis[m.ID]; ok {
			m.Model, m.Serial = c.model, c.serial
		}
		if v, ok := table[m.ID]; ok {
			m.Release = v.release
			if m.Model == "" {
				m.Model = v.model
			}
		}
	}
	return cleanMembers(ms)
}
