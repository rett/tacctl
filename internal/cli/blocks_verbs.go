package cli

// The verbs of the configuration blocks (0.2.7, docs/plans/0.2.7-blocks-
// plan.md B4): list, show, check, set and remove, for a scope's blocks
// (scope_block.go) and for one device's own (device_block.go). One engine
// serves both levels: a blockCtx names the level, and the verbs are its
// methods. edit and adopt (blocks_edit.go, blocks_adopt.go; B5 and B6) end
// as set does, through review and install.
//
// What a block holds is a secret (a community string, a trap group's name, an
// NTP key) or a banner that names a site, so nothing here prints a word of
// one but 'show --reveal': every other output is a count, a line number or
// the marks of blocks.Elide. A comment line of a block may hold anything, so
// an elided view never carries one.

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

// blockWords are the block names, for the usage and completion.
var blockWords = strings.Join(blocks.KnownBlocks, "|")

// blockCtx is the level a block verb works on.
type blockCtx struct {
	inv    *invocation
	level  blocks.Level
	vendor string
	// scope is the scope of the level: the scope itself, or the scope that
	// answers the device.
	scope string
	// dev is the registered device of a device level.
	dev *devreg.Entry
	// restricted is an engineer: the verbs read, and only their own scopes.
	restricted bool
}

func (c *blockCtx) isDevice() bool { return c.level.IsDevice() }

// what is the level as a message names it.
func (c *blockCtx) what() string {
	if c.isDevice() {
		return "device '" + c.dev.Name + "'"
	}
	return "scope '" + c.level.Scope + "'"
}

// verb is the command line up to the verb: 'tacctl scope block lab juniper'
// or 'tacctl device block sw1'.
func (c *blockCtx) verb() string {
	if c.isDevice() {
		return "tacctl device block " + shellWord(c.dev.Name)
	}
	return "tacctl scope block " + c.level.Scope + " " + c.vendor
}

func shellWord(s string) string {
	if s == "" || strings.ContainsAny(s, " \t'\"\\$`") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}

// layer is the level's layer of the resolution.
func (c *blockCtx) layer() blocks.Layer {
	if c.isDevice() {
		return blocks.LayerDevice
	}
	return blocks.LayerScope
}

func (c *blockCtx) store() *blocks.Store { return c.inv.deviceBlockStore() }

// names are the blocks the manifest names for the level.
func (c *blockCtx) names() []string {
	cfg := c.inv.app.Conf()
	if c.isDevice() {
		return policy.DeviceBlockNames(cfg, c.level.Device, c.vendor)
	}
	return policy.BlockNames(cfg, c.level.Scope, c.vendor)
}

func (c *blockCtx) listed(block string) bool { return slices.Contains(c.names(), block) }

func (c *blockCtx) setListed(block string, on bool) error {
	cfg := c.inv.app.Conf()
	if c.isDevice() {
		return policy.SetDeviceBlockInForce(cfg, c.level.Device, c.vendor, block, on)
	}
	return policy.SetBlockInForce(cfg, c.level.Scope, c.vendor, block, on)
}

// logName is how the audit log names a block: scope/juniper/snmp, or
// _devices/<device>/juniper/snmp.
func (c *blockCtx) logName(block string) string {
	if c.isDevice() {
		return blocks.DevicesDir + "/" + strings.ToLower(c.level.Device) + "/" + c.vendor + "/" + block
	}
	return c.level.Scope + "/" + c.vendor + "/" + block
}

// blockFile is a block's file and whether the manifest names it.
type blockFile struct {
	text   []byte
	exists bool
	listed bool
	err    error
}

func (c *blockCtx) file(block string) blockFile {
	f := blockFile{listed: c.listed(block)}
	text, err := c.store().Read(c.level, c.vendor, block)
	switch {
	case err == blocks.ErrNotFound:
	case err != nil:
		f.err = err
	default:
		f.text, f.exists = text, true
	}
	return f
}

// state is the word list and show use for a block.
func (f blockFile) state() string {
	switch {
	case f.err != nil:
		return "unreadable"
	case f.listed && f.exists:
		return "in force"
	case f.listed:
		return "no file"
	case f.exists:
		return "ignored (not in tacctl.yaml)"
	}
	return "none"
}

// --- the engine's helpers ---------------------------------------------------------

// logReveal is the audit line of a reveal, whoever makes it: the name of the
// block, never a word of it.
func (c *blockCtx) logReveal(block string) {
	c.inv.secretRead("block", c.logName(block))
}

// requireSuperuser refuses a verb that changes something for an engineer.
func (c *blockCtx) requireSuperuser(sub string) error {
	if !c.restricted {
		return nil
	}
	return c.inv.deniedUsage(reasonSuperuser, "The engineer tier reads the configuration blocks of "+c.what()+" (list, show, check); "+sub+
		" is the superuser's. Nothing was changed.")
}

// readInput is the text of --file <path> or of a lone '-' (standard input):
// the file is read as the caller (a path a lower tier names is never read
// with root's rights), at most blocks.MaxSize bytes. source says where it
// came from, for the output.
func (c *blockCtx) readInput(p Parsed, usage string) (text []byte, source string, err error) {
	inv := c.inv
	path := p.Value("--file")
	stdin := len(p.Args) > 1 && p.Args[1] == "-"
	switch {
	case len(p.Args) > 1 && p.Args[1] != "-":
		return nil, "", inv.usageErr("Unknown argument: '"+p.Args[1]+"'", "Usage: "+usage)
	case path != "" && stdin:
		return nil, "", inv.usageErr("--file and - (standard input) are two sources; give one.", "Usage: "+usage)
	case p.Has("--file") && path == "":
		return nil, "", inv.usageErr("--file takes a path.", "Usage: "+usage)
	case path != "":
		var data []byte
		err := inv.asCaller(func() error {
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			st, err := f.Stat()
			if err != nil {
				return err
			}
			if !st.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", path)
			}
			if st.Size() > blocks.MaxSize {
				return fmt.Errorf("%s is %d bytes: a block is at most %d (256 KiB)", path, st.Size(), blocks.MaxSize)
			}
			data, err = io.ReadAll(io.LimitReader(f, blocks.MaxSize+1))
			if err == nil && len(data) > blocks.MaxSize {
				err = fmt.Errorf("%s is larger than %d bytes (256 KiB)", path, blocks.MaxSize)
			}
			return err
		})
		if err != nil {
			return nil, "", inv.usageErr("Cannot read the file: " + strings.TrimPrefix(blockPathProblem(err), "open ") + ". Nothing was changed.")
		}
		return data, "the file " + path, nil
	case stdin:
		data, err := io.ReadAll(io.LimitReader(inv.app.Stdin, blocks.MaxSize+1))
		if err != nil {
			return nil, "", inv.usageErr("Cannot read standard input: " + err.Error() + ". Nothing was changed.")
		}
		if len(data) > blocks.MaxSize {
			return nil, "", inv.usageErr("Standard input is larger than " + strconv.Itoa(blocks.MaxSize) + " bytes (256 KiB): a block is at most that. Nothing was changed.")
		}
		return data, "standard input", nil
	}
	return nil, "", nil
}

// blockPathProblem is an error of the file as the message words it.
func blockPathProblem(err error) string {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Path + ": " + pe.Err.Error()
	}
	return err.Error()
}

// ownLines splits canonical text into its lines (no trailing empty one).
func ownLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// --- units: the statements of a block, for the diff and the layers -----------------

// blockUnit is one statement of a block (the login message, being one
// statement in several lines, is one unit): full is its text with the
// strings, elided what may be shown, key what groups the statements of one
// object.
type blockUnit struct {
	full, elided, key string
}

// blockUnits are the units of a parsed block in the canonical order.
func blockUnits(doc blocks.Doc) []blockUnit {
	switch b := doc.(type) {
	case *blocks.SNMPBlock:
		return pairUnits(ownLines(b.String(false)), ownLines(b.String(true)), snmpKey)
	case *blocks.IOSSNMPBlock:
		// an access list is one unit (it is owned whole): its header and its
		// entries; every other statement is a line of its own
		full, elided := blocks.IOSSNMPUnits(b), blocks.IOSSNMPUnits(blocks.ElideIOSSNMP(b))
		var out []blockUnit
		for i := range elided {
			f := elided[i]
			if len(full) == len(elided) {
				f = full[i]
			}
			out = append(out, blockUnit{full: strings.Join(f, "\n"), elided: strings.Join(elided[i], "\n"), key: elided[i][0]})
		}
		nf, ne := blocks.IOSNotManagedLines(b, false), blocks.IOSNotManagedLines(b, true)
		for i := range ne {
			f := ne[i]
			if len(nf) == len(ne) {
				f = nf[i]
			}
			out = append(out, blockUnit{full: f, elided: ne[i], key: ne[i]})
		}
		return out
	case *blocks.IOSSystemBlock:
		// the banner is one unit (its lines), every other statement a line
		// of its own; its text and a key's string are shown elided
		var out []blockUnit
		rest := *b
		if b.Banner != nil {
			m := &blocks.IOSSystemBlock{Banner: b.Banner}
			out = append(out, blockUnit{
				full:   strings.Join(ownLines(m.String(false)), "\n"),
				elided: strings.Join(ownLines(m.String(true)), "\n"),
				key:    "login banner",
			})
			rest.Banner = nil
		}
		return append(out, pairUnits(ownLines(rest.String(false)), ownLines(rest.String(true)), func(s string) string { return s })...)
	case *blocks.SystemBlock:
		var out []blockUnit
		rest := *b
		if b.Message != nil {
			m := &blocks.SystemBlock{Message: b.Message}
			out = append(out, blockUnit{
				full:   strings.Join(ownLines(m.String(false)), "\n"),
				elided: strings.Join(ownLines(m.String(true)), "\n"),
				key:    "login message",
			})
			rest.Message = nil
		}
		return append(out, pairUnits(ownLines(rest.String(false)), ownLines(rest.String(true)), func(s string) string { return s })...)
	}
	return nil
}

// snmpKey is the object a statement of the snmp block belongs to: its first
// four words (set snmp community <name>).
func snmpKey(line string) string {
	f := strings.Fields(line)
	if len(f) >= 4 && f[1] == "snmp" && (f[2] == "community" || f[2] == "trap-group") {
		return strings.Join(f[:4], " ")
	}
	return line
}

// pairUnits pairs the full lines with the elided ones; a block's two forms
// have the same number of lines, and when they do not the elided text stands
// for both (the strings are never at risk).
func pairUnits(full, elided []string, key func(string) string) []blockUnit {
	out := make([]blockUnit, len(elided))
	for i, e := range elided {
		f := e
		if len(full) == len(elided) {
			f = full[i]
		}
		out[i] = blockUnit{full: f, elided: e, key: key(e)}
	}
	return out
}

// unitDiff are the units only in newer (added) and only in older (removed),
// compared by their full text and shown elided, in their blocks' order; same
// counts the units both have.
func unitDiff(older, newer []blockUnit) (added, removed []blockUnit, same int) {
	left := map[string]int{}
	for _, u := range older {
		left[u.full]++
	}
	have := map[string]int{}
	for _, u := range newer {
		have[u.full]++
		if left[u.full] > 0 {
			left[u.full]--
			same++
			continue
		}
		added = append(added, u)
	}
	for _, u := range older {
		if have[u.full] > 0 {
			have[u.full]--
			continue
		}
		removed = append(removed, u)
	}
	return added, removed, same
}

// --- what a block holds, in counts -------------------------------------------------

// blockCounts is what a block states, as words: the objects tacctl owns once
// it is in force.
func blockCounts(doc blocks.Doc) string {
	switch b := doc.(type) {
	case *blocks.SNMPBlock:
		var parts []string
		add := func(n int, one, many string) {
			if n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, plural(n, one, many)))
			}
		}
		add(len(b.Communities), "community", "communities")
		add(len(b.TrapGroups), "trap group", "trap groups")
		add(len(b.TrapOptions), "trap-options leaf", "trap-options leaves")
		add(len(b.NotManaged), "delete line", "delete lines")
		if len(parts) == 0 {
			return "nothing"
		}
		return strings.Join(parts, ", ")
	case *blocks.IOSSNMPBlock:
		var parts []string
		add := func(n int, one, many string) {
			if n > 0 {
				parts = append(parts, fmt.Sprintf("%d %s", n, plural(n, one, many)))
			}
		}
		add(len(b.Communities), "community", "communities")
		add(len(b.ACLs), "access list", "access lists")
		add(len(b.Hosts), "trap host", "trap hosts")
		if b.TrapSource != nil {
			add(1, "trap source", "trap sources")
		}
		add(len(b.Traps), "'enable traps' line", "'enable traps' lines")
		add(len(b.NotManaged), "no line", "no lines")
		if len(parts) == 0 {
			return "nothing"
		}
		return strings.Join(parts, ", ")
	case *blocks.IOSSystemBlock:
		n := len(blocks.IOSSystemUnits(b))
		parts := []string{fmt.Sprintf("%d %s", n, plural(n, "statement", "statements"))}
		if b.Banner != nil {
			parts = append(parts, fmt.Sprintf("a login banner of %d %s", b.Banner.Lines(), plural(b.Banner.Lines(), "line", "lines")))
		}
		if d := len(b.NotManaged); d > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", d, plural(d, "no line", "no lines")))
		}
		return strings.Join(parts, ", ")
	case *blocks.SystemBlock:
		n := len(blocks.SystemStatements(b))
		parts := []string{fmt.Sprintf("%d %s", n, plural(n, "statement", "statements"))}
		if b.Message != nil {
			parts = append(parts, fmt.Sprintf("a login message of %d %s", b.Message.Lines(), plural(b.Message.Lines(), "line", "lines")))
		}
		if d := len(b.NotManaged); d > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", d, plural(d, "delete line", "delete lines")))
		}
		return strings.Join(parts, ", ")
	}
	return ""
}

// secretStatements is how many statements of the block carry a string that
// must not be printed: a community or trap group (its name is the string), an
// NTP key (its value).
func secretStatements(doc blocks.Doc) int {
	n := 0
	switch b := doc.(type) {
	case *blocks.SNMPBlock:
		for _, s := range blocks.Statements(b) {
			if strings.HasPrefix(s, "set snmp community ") || strings.HasPrefix(s, "set snmp trap-group ") {
				n++
			}
		}
	case *blocks.IOSSNMPBlock:
		for _, s := range blocks.IOSSNMPStatements(b) {
			if strings.HasPrefix(s, "snmp-server community ") || strings.HasPrefix(s, "snmp-server host ") {
				n++
			}
		}
	case *blocks.IOSSystemBlock:
		for _, s := range blocks.IOSSystemStatements(b) {
			if blocks.IsIOSSecretStatement(s) {
				n++
			}
		}
	case *blocks.SystemBlock:
		for _, s := range blocks.SystemStatements(b) {
			if blocks.IsSecretStatement(s) {
				n++
			}
		}
	}
	return n
}

func humanSize(n int) string {
	if n >= 1024 {
		return fmt.Sprintf("%.1f KiB", float64(n)/1024)
	}
	return fmt.Sprintf("%d B", n)
}

// --- list -------------------------------------------------------------------------

func (c *blockCtx) list() error {
	inv := c.inv
	title := "Configuration blocks of " + c.what() + " (" + c.vendor + ")"
	files, err := c.store().List(c.level, c.vendor)
	if err != nil {
		return err
	}
	listed := c.names()
	var rows []string
	for _, b := range blocks.KnownBlocks {
		if slices.Contains(listed, b) || slices.Contains(files, b) {
			rows = append(rows, b)
		}
	}
	findings, err := c.findings(listed)
	if err != nil {
		return err
	}
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	if len(rows) == 0 && len(findings) == 0 {
		inv.echo("  none: " + c.what() + " has no " + c.vendor + " block.")
	}
	for _, b := range rows {
		f := c.file(b)
		size, content := "-", "-"
		if f.exists {
			size = humanSize(len(f.text))
			doc, fs, lerr := blocks.LintFor(c.vendor, b, string(f.text), c.layer())
			switch {
			case lerr != nil:
				content = "not built for " + c.vendor + " (" + c.verb() + " remove " + b + ")"
			case blocks.HasErrors(fs):
				n := 0
				for _, x := range fs {
					if x.Severity == blocks.SevError {
						n++
					}
				}
				content = fmt.Sprintf("%d %s (%s check %s)", n, plural(n, "error", "errors"), c.verb(), b)
			default:
				content = blockCounts(doc)
			}
		}
		inv.echo(fmt.Sprintf("  %-8s %-30s %-9s %s", b, f.state(), size, content))
	}
	if c.isDevice() {
		if under := policy.BlockNames(inv.app.Conf(), c.scope, c.vendor); len(under) > 0 {
			inv.echo("  beneath it, scope '" + c.scope + "' has: " + strings.Join(under, ", ") + " (tacctl scope block " + c.scope + " " + c.vendor + " list)")
		}
	}
	if len(findings) > 0 {
		inv.echo("")
		inv.echo("  Findings:")
		for _, f := range findings {
			inv.echo("    " + f)
		}
	}
	inv.echo("")
	return nil
}

// findings are what the manifest and the files disagree about for this
// level, as lines: a file no list names, a name with no file and, for a
// device, the vendor and registry orphans.
func (c *blockCtx) findings(listed []string) ([]string, error) {
	var out []string
	st := c.store()
	if c.isDevice() {
		vendorOf := func(device string) (string, bool) {
			f, err := devreg.Load(c.inv.app.Paths.DevicesFile)
			if err != nil {
				return "", false
			}
			d := f.Find(device)
			if d == nil {
				return "", false
			}
			return d.Vendor, true
		}
		fs, err := st.VerifyDevices(policy.DeviceBlockManifest(c.inv.app.Conf()), vendorOf)
		if err != nil {
			return nil, err
		}
		for _, f := range fs {
			if strings.EqualFold(f.Level.Device, c.level.Device) {
				out = append(out, f.Text)
			}
		}
		return out, nil
	}
	fs, err := st.Verify(c.level, c.vendor, listed)
	if err != nil {
		return nil, err
	}
	for _, f := range fs {
		out = append(out, f.Text)
	}
	return out, nil
}

// --- show -------------------------------------------------------------------------

func (c *blockCtx) show(block string, reveal, effective bool) error {
	inv := c.inv
	if effective {
		return c.showEffective(block, reveal)
	}
	f := c.file(block)
	switch {
	case f.err != nil:
		return f.err
	case !f.exists && f.listed:
		return inv.usageErr("The "+block+" block of "+c.what()+" is named in tacctl.yaml but has no file, so it renders nothing.",
			"Set it with: "+c.verb()+" set "+block+" --file <path>")
	case !f.exists:
		return inv.usageErr(upperFirst(c.what()) + " has no " + block + " block.")
	}
	state := ""
	if !f.listed {
		state = "; not in force: tacctl.yaml does not name it"
	}
	if reveal {
		c.logReveal(block)
		inv.echo("# " + upperFirst(c.what()) + ", " + c.vendor + " " + block + " block, as stored (the strings are shown" + state + ")")
		inv.write(string(f.text))
		if !strings.HasSuffix(string(f.text), "\n") {
			inv.echo("")
		}
		return nil
	}
	doc, fs, err := blocks.LintFor(c.vendor, block, string(f.text), c.layer())
	if err != nil {
		return err
	}
	if blocks.HasErrors(fs) {
		return inv.usageErr(append([]string{"The " + block + " block of " + c.what() + " has errors, so it cannot be shown elided:"},
			c.errorLines(fs)...)...)
	}
	inv.echo("# " + upperFirst(c.what()) + ", " + c.vendor + " " + block + " block, elided (--reveal shows the strings" + state + "; comments are not shown)")
	inv.write(doc.String(true))
	return nil
}

// errorLines are the error findings, indented for a message.
func (c *blockCtx) errorLines(fs []blocks.Finding) []string {
	var out []string
	for _, f := range fs {
		if f.Severity == blocks.SevError {
			out = append(out, "  "+f.String())
		}
	}
	return out
}

// showEffective is a device's block as it is rendered: the scope's, the
// device's own over it, with a comment per object that says which layer it
// came from.
func (c *blockCtx) showEffective(block string, reveal bool) error {
	inv := c.inv
	st, cfg := c.store(), inv.app.Conf()
	scopeText, err := policy.LayerTextFor(st, cfg, c.vendor, blocks.ScopeLevel(c.scope), block)
	if err != nil {
		return err
	}
	devText, err := policy.LayerTextFor(st, cfg, c.vendor, c.level, block)
	if err != nil {
		return err
	}
	if scopeText == nil && devText == nil {
		return inv.usageErr("Neither scope '" + c.scope + "' nor " + c.what() + " has a " + block + " block in force.")
	}
	var scopeDoc, devDoc, res blocks.Doc
	layers := [2]blocks.Layer{blocks.LayerScope, blocks.LayerDevice}
	for i, t := range [][]byte{scopeText, devText} {
		if t == nil {
			continue
		}
		doc, fs, err := blocks.LintFor(c.vendor, block, string(t), layers[i])
		if err != nil {
			return err
		}
		if blocks.HasErrors(fs) {
			who := "scope '" + c.scope + "'"
			verb := "tacctl scope block " + c.scope + " " + c.vendor
			if i == 1 {
				who, verb = c.what(), c.verb()
			}
			return inv.usageErr(append([]string{"The " + block + " block of " + who + " has errors, so it cannot be resolved: run " + verb + " check " + block},
				c.errorLines(fs)...)...)
		}
		if i == 0 {
			scopeDoc = doc
		} else {
			devDoc = doc
		}
	}
	switch {
	case block == blocks.BlockSNMP && c.vendor == blocks.VendorCisco:
		var s, d *blocks.IOSSNMPBlock
		if scopeDoc != nil {
			s = scopeDoc.(*blocks.IOSSNMPBlock)
		}
		if devDoc != nil {
			d = devDoc.(*blocks.IOSSNMPBlock)
		}
		res = blocks.ResolveIOSSNMP(nil, s, d)
	case block == blocks.BlockSNMP:
		var s, d *blocks.SNMPBlock
		if scopeDoc != nil {
			s = scopeDoc.(*blocks.SNMPBlock)
		}
		if devDoc != nil {
			d = devDoc.(*blocks.SNMPBlock)
		}
		res = blocks.Resolve(nil, s, d)
	case c.vendor == blocks.VendorCisco:
		var s, d *blocks.IOSSystemBlock
		if scopeDoc != nil {
			s = scopeDoc.(*blocks.IOSSystemBlock)
		}
		if devDoc != nil {
			d = devDoc.(*blocks.IOSSystemBlock)
		}
		res = blocks.ResolveIOSSystem(nil, s, d)
	default:
		var s, d *blocks.SystemBlock
		if scopeDoc != nil {
			s = scopeDoc.(*blocks.SystemBlock)
		}
		if devDoc != nil {
			d = devDoc.(*blocks.SystemBlock)
		}
		res = blocks.ResolveSystem(nil, s, d)
	}
	if reveal {
		if scopeText != nil {
			inv.secretRead("block", c.scope+"/"+c.vendor+"/"+block)
		}
		if devText != nil {
			c.logReveal(block)
		}
	}
	fromDevice := map[string]bool{}
	if devDoc != nil {
		for _, u := range blockUnits(devDoc) {
			fromDevice[u.full] = true
		}
	}
	mode := "elided"
	if reveal {
		mode = "the strings are shown"
	}
	inv.echo("# " + upperFirst(c.what()) + ", " + c.vendor + " " + block + " block as rendered: scope '" + c.scope + "' with the device's own over it (" + mode + "; comments are not shown)")
	prevKey, prevFrom := "", ""
	for _, u := range blockUnits(res) {
		from := "scope '" + c.scope + "'"
		if fromDevice[u.full] {
			from = c.what()
		}
		if u.key != prevKey || from != prevFrom {
			inv.echo("# from " + from)
			prevKey, prevFrom = u.key, from
		}
		text := u.elided
		if reveal {
			text = u.full
		}
		inv.echo(text)
	}
	return nil
}

// --- check ------------------------------------------------------------------------

// blockCheck is the result of looking at a block text.
type blockCheck struct {
	source   string
	text     []byte
	doc      blocks.Doc
	findings []blocks.Finding
	// current is the file in force parsed (nil when there is none or it does
	// not parse), and hasCurrent whether there is a file at all.
	current blocks.Doc
	// collision are the refusals of the scope's own community (errors).
	collision []string
	// added, removed and same are the diff against the file in force.
	added, removed []blockUnit
	same           int
	hasCurrent     bool
}

func (b *blockCheck) errors() int {
	n := len(b.collision)
	for _, f := range b.findings {
		if f.Severity == blocks.SevError {
			n++
		}
	}
	return n
}

// examine lints a text and measures it against the file in force.
func (c *blockCtx) examine(block string, text []byte, source string) (*blockCheck, error) {
	doc, fs, err := blocks.LintFor(c.vendor, block, string(text), c.layer())
	if err != nil {
		return nil, err
	}
	bc := &blockCheck{source: source, text: text, doc: doc, findings: fs}
	if blocks.HasErrors(fs) {
		return bc, nil
	}
	if cur := c.file(block); cur.exists {
		bc.hasCurrent = true
		if d, cfs, err := blocks.LintFor(c.vendor, block, string(cur.text), c.layer()); err == nil && !blocks.HasErrors(cfs) {
			bc.current = d
		}
	}
	var old []blockUnit
	if bc.current != nil {
		old = blockUnits(bc.current)
	}
	if !bc.hasCurrent || bc.current != nil {
		bc.added, bc.removed, bc.same = unitDiff(old, blockUnits(doc))
	}
	bc.collision = c.collisions(block, doc)
	return bc, nil
}

// collisions are the refusals of a block community that is the community the
// scope's own SNMP settings render (the device could not hold both): the text
// is the one the renderers refuse with, and holds no string.
func (c *blockCtx) collisions(block string, doc blocks.Doc) []string {
	if block != blocks.BlockSNMP {
		return nil
	}
	var jb *blocks.SNMPBlock
	var cb *blocks.IOSSNMPBlock
	switch s := doc.(type) {
	case *blocks.SNMPBlock:
		jb = s
	case *blocks.IOSSNMPBlock:
		cb = s
	}
	if jb == nil && cb == nil {
		return nil
	}
	in := devices.SNMPInput{}
	if c.isDevice() {
		in = deviceSNMPValues(*c.dev)
	}
	in, err := c.inv.walkthroughSNMP(c.scope, in)
	if err != nil {
		return nil
	}
	d := devices.Data{SNMP: in, Blocks: devices.Blocks{Scope: c.scope, SNMP: jb, CiscoSNMP: cb}}
	if cb != nil {
		// the scope's management access list is a name a block may not define
		d.ACL.Name = c.inv.readMgmtACLName(c.vendor, c.scope)
	}
	if c.isDevice() {
		d.Blocks.Device, d.Blocks.SNMPLayer = c.dev.Name, devices.LayerDevice
	}
	err = d.BlockProblem(devices.Request{Vendor: c.vendor, Scope: c.scope})
	if err == nil {
		return nil
	}
	return msgs(err)
}

// print is the report of check and the preview of set.
func (c *blockCtx) printCheck(block string, bc *blockCheck, withVerdict bool) {
	inv := c.inv
	title := "The " + block + " block of " + c.what() + " (" + c.vendor + "): " + bc.source + ", " + strconv.Itoa(len(bc.text)) + " bytes"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	if len(bc.findings) == 0 && len(bc.collision) == 0 {
		inv.echo("  no findings")
	}
	for _, f := range bc.findings {
		inv.echo("  " + f.String())
	}
	for _, m := range bc.collision {
		inv.echo("  error: " + m)
	}
	if blocks.HasErrors(bc.findings) {
		if withVerdict {
			inv.echo("")
			inv.echo("  " + strconv.Itoa(bc.errors()) + " " + plural(bc.errors(), "error", "errors") + ": the block cannot be set until they are fixed.")
			inv.echo("")
		}
		return
	}
	inv.echo("")
	inv.echo("  Owned by tacctl once in force: " + blockCounts(bc.doc))
	if n := secretStatements(bc.doc); n > 0 {
		inv.echo("  Statements that carry a secret: " + strconv.Itoa(n) + " (shown elided; 'show --reveal' prints them)")
	} else {
		inv.echo("  Statements that carry a secret: none")
	}
	switch {
	case !bc.hasCurrent:
		inv.echo("  No file in force: every statement is new.")
	case bc.current == nil:
		inv.echo("  The file in force has errors and is not compared.")
	case len(bc.added) == 0 && len(bc.removed) == 0:
		inv.echo("  No change against the file in force (" + strconv.Itoa(bc.same) + " " + plural(bc.same, "statement", "statements") + ").")
	}
	if len(bc.added)+len(bc.removed) > 0 && (!bc.hasCurrent || bc.current != nil) {
		inv.echo("  Against the file in force, elided (" + strconv.Itoa(bc.same) + " unchanged; a string that changed shows as the same mark removed and added):")
		for _, u := range bc.removed {
			for _, l := range strings.Split(u.elided, "\n") {
				inv.echo("    - " + l)
			}
		}
		for _, u := range bc.added {
			for _, l := range strings.Split(u.elided, "\n") {
				inv.echo("    + " + l)
			}
		}
	}
	if withVerdict {
		inv.echo("")
		if bc.errors() > 0 {
			inv.echo("  " + strconv.Itoa(bc.errors()) + " " + plural(bc.errors(), "error", "errors") + ": the block cannot be set until they are fixed.")
		} else {
			inv.echo("  ok.")
		}
		inv.echo("")
	}
}

// check is 'check <block> [--file <path>|-] [--against ...]'.
func (c *blockCtx) check(block string, p Parsed, against string, usage string) error {
	inv := c.inv
	text, source, err := c.readInput(p, usage)
	if err != nil {
		return err
	}
	if source == "" {
		f := c.file(block)
		switch {
		case f.err != nil:
			return f.err
		case !f.exists && f.listed:
			return inv.usageErr("The "+block+" block of "+c.what()+" is named in tacctl.yaml but has no file, so there is nothing to check.",
				"Check a text before setting it: "+c.verb()+" check "+block+" --file <path>")
		case !f.exists:
			return inv.usageErr(upperFirst(c.what()) + " has no " + block + " block to check. Check a text with: " + c.verb() + " check " + block + " --file <path>")
		}
		text, source = f.text, "the file in force"
		if !f.listed {
			source = "the file, which is not in force (tacctl.yaml does not name it)"
		}
	} else if len(text) == 0 {
		return inv.usageErr("The text is empty.")
	}
	bc, err := c.examine(block, text, source)
	if err != nil {
		return err
	}
	c.printCheck(block, bc, true)
	if bc.errors() > 0 {
		return exit(1)
	}
	if against == "" {
		return nil
	}
	return c.against(block, text, against)
}

// against plans the device with the checked text in force and prints the
// statements for the block's section: nothing is written and no device is
// reached; the plan is made from the device's last pull, exactly as
// 'device config plan' makes it, with every secret as a placeholder.
func (c *blockCtx) against(block string, text []byte, device string) error {
	inv := c.inv
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, err := inv.deviceFind(res, device)
	if err != nil {
		return err
	}
	switch {
	case e.Source != devreg.SourceDevice:
		return inv.usageErr("'" + e.Name + "' is an enrolled Linux host, not a device with a configuration.")
	case e.Vendor != c.vendor:
		return inv.usageErr("'" + e.Name + "' is not " + vendorWordOf(c.vendor) + " device: the blocks of vendor " + c.vendor + " are its vendor's syntax, and its configuration is not planned from one.")
	case !c.isDevice() && e.Scope != c.level.Scope:
		return inv.usageErr("Device '" + e.Name + "' is in " + scopeWord(e.Scope) + ", not in scope '" + c.level.Scope + "': a block of this scope is not rendered for it.")
	case !e.Configured:
		return inv.usageErr("Device '" + e.Name + "' is in no scope: nothing is rendered for it.")
	}
	section := "snmp"
	if block == blocks.BlockSystem {
		section = "system"
	}
	r := inv.newManagedRender(managedOptions{}, inv.callerScopes().restricted)
	r.override = &blockOverride{level: c.level, block: block, text: text}
	r.prepare([]devreg.Entry{e})
	staleDays := devreg.DefaultStaleDays
	if f, _, err := inv.deviceLoad(); err == nil && f.StaleDays > 0 {
		staleDays = f.StaleDays
	}
	run := &planRun{inv: inv, opt: planOptions{sections: []string{section}, noSecrets: true}, render: r, store: inv.configStore(),
		user: inv.sudoUser(), now: inv.app.Knobs.Now(), stale: staleDays, failed: map[string]string{},
		wrap: plan.Wrapper{ConfirmMinutes: inv.confirmTimeout()}, dry: true}
	pd := run.planOne(e)
	title := "Plan of " + e.Name + " with this text in force"
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	if !pd.planned() {
		why := pd.cannot
		if strings.HasPrefix(why, "not pulled") {
			why = "pull the device first: tacctl device config pull " + e.Name + " (the plan is made from its stored pull; nothing was read from it)"
		}
		inv.echo("  cannot be planned: " + why)
		if strings.Contains(why, "newer than the pull") {
			inv.echo("  A pull reads the system settings only for a scope that has the block in force: set the block, pull the device, then plan it.")
		}
		inv.echo("")
		return exit(1)
	}
	d := pd.d
	inv.echo("  From the pull of " + pd.h.Pulled.UTC().Format("2006-01-02 15:04") + " (UTC); nothing was written and no device was reached.")
	state := ""
	for _, s := range d.Sections {
		if s.Name == section {
			state = s.State
		}
	}
	n := 0
	for _, l := range d.Lines {
		if l.Section == section {
			n++
		}
	}
	inv.echo("  Section " + section + ": " + state + ", " + strconv.Itoa(n) + " " + plural(n, "statement", "statements"))
	var ctx []string
	for _, l := range d.Lines {
		if l.Section != section {
			continue
		}
		shown := l.Shown()
		// the login message is a banner: its size is what is printed
		if strings.HasPrefix(shown, blocks.MessageStatement) {
			if sb, ok := messageOf(text); ok {
				shown = blocks.MessageStatement + blocks.ElideSystem(&blocks.SystemBlock{Message: sb}).Message.Body
			}
		}
		// an IOS banner is several lines: its text is never printed, its size
		// is
		if strings.HasPrefix(shown, blocks.IOSBannerHead) && strings.Contains(shown, "\n") {
			if bb, ok := bannerOf(text); ok {
				shown = blocks.IOSBannerHead + blocks.ElideIOSSystem(&blocks.IOSSystemBlock{Banner: bb}).Banner.Body
			}
		}
		// an IOS entry of a list or a submode is shown under its header
		if !slices.Equal(ctx, l.Context) {
			for _, h := range l.Context {
				inv.echo("    " + h)
			}
			ctx = slices.Clone(l.Context)
		}
		if l.Op == plan.OpNo {
			shown = "no " + shown
		}
		inv.echo("    " + strings.Repeat(" ", len(l.Context)) + shown)
	}
	for _, s := range d.Skipped {
		if s.Section == section {
			inv.echo("  not planned: " + s.Why)
		}
	}
	inv.echo("")
	return nil
}

// messageOf is the login message of a system block text.
func messageOf(text []byte) (*blocks.LoginMessage, bool) {
	b, fs := blocks.ParseSystem(string(text))
	if blocks.HasErrors(fs) || b.Message == nil {
		return nil, false
	}
	return b.Message, true
}

// bannerOf is the login banner of an IOS system block text.
func bannerOf(text []byte) (*blocks.LoginMessage, bool) {
	b, fs := blocks.ParseIOSSystem(string(text))
	if blocks.HasErrors(fs) || b.Banner == nil {
		return nil, false
	}
	return b.Banner, true
}

func scopeWord(scope string) string {
	if scope == "" {
		return "no scope"
	}
	return "scope '" + scope + "'"
}

// --- set --------------------------------------------------------------------------

// confWritable is nil when tacctl.yaml can be written: a block is in force
// only while it names it, so a file written beside a list that cannot be
// updated would be a block nobody sees.
func (inv *invocation) confWritable() error {
	cfg := inv.app.Conf()
	if _, problem := conf.ReadOverrides(cfg.Path); problem != "" {
		return inv.usageErr("tacctl.yaml cannot be read: "+problem+".", "Nothing was changed: a block is in force only while tacctl.yaml names it.")
	}
	dir := filepath.Dir(cfg.Path)
	if err := unix.Access(dir, unix.W_OK); err != nil {
		return inv.usageErr("tacctl.yaml cannot be written ("+dir+": "+err.Error()+").", "Nothing was changed: a block is in force only while tacctl.yaml names it.")
	}
	return nil
}

func (c *blockCtx) set(block string, p Parsed, usage string) error {
	inv := c.inv
	a := inv.app
	if err := c.requireSuperuser("set"); err != nil {
		return err
	}
	stdin := len(p.Args) > 1 && p.Args[1] == "-"
	if !p.Has("--file") && !stdin {
		return inv.usageErr("Give the block's text with --file <path>, or - for standard input.", "Usage: "+usage)
	}
	// Standard input is the block: it cannot also answer the question.
	if stdin && !p.Has("-y") && !a.Prompter().Interactive() {
		return inv.usageErr("The block comes on standard input, so there is nothing to answer the question with: add -y to set it. Nothing was changed.")
	}
	text, source, err := c.readInput(p, usage)
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(text))) == 0 {
		return inv.usageErr("The text is empty. To take a block away: " + c.verb() + " remove " + block + ". Nothing was changed.")
	}
	if !strings.HasSuffix(string(text), "\n") {
		text = append(text, '\n')
	}
	bc, err := c.examine(block, text, source)
	if err != nil {
		return err
	}
	if bc.errors() > 0 {
		c.printCheck(block, bc, true)
		inv.app.Out.ErrorE("Nothing was written.")
		return exit(1)
	}
	if bc.doc.Empty() {
		return inv.usageErr("The text states nothing (comments and blank lines only). To take a block away: " + c.verb() + " remove " + block + ". Nothing was changed.")
	}
	if err := inv.confWritable(); err != nil {
		return err
	}
	cur := c.file(block)
	if cur.err != nil {
		return cur.err
	}
	if cur.exists && cur.listed && string(cur.text) == string(text) {
		a.Out.Info("The " + block + " block of " + c.what() + " is this text already; nothing was changed.")
		return nil
	}
	if !c.review(block, bc, p.Has("-y")) {
		return nil
	}
	return c.install(block, text, bc, cur, "set")
}

// review shows the check and the diff of a text that passed, says what
// installing it does and asks (unless yes): false is a no, which is no
// change. It is the question of set, edit and adopt.
func (c *blockCtx) review(block string, bc *blockCheck, yes bool) bool {
	inv := c.inv
	a := inv.app
	c.printCheck(block, bc, false)
	inv.echo("  This puts the " + block + " block of " + c.what() + " in force. It reaches devices through 'tacctl device config plan'; nothing is restarted.")
	if !yes && !a.Prompter().ConfirmPrefix("  Set this block? [y/N]: ") {
		a.Out.Info("Aborted.")
		return false
	}
	return true
}

// install is the write of set, edit and adopt, after the question: the
// snapshot first, then the file and the entry of tacctl.yaml together (the
// file is put back when the entry cannot be written), then the audit line
// 'block-<event>' (name, size and counts, never a value). cur is the file as
// it was.
func (c *blockCtx) install(block string, text []byte, bc *blockCheck, cur blockFile, event string) error {
	inv := c.inv
	a := inv.app
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	st := c.store()
	if err := st.Write(c.level, c.vendor, block, text); err != nil {
		return err
	}
	if err := c.setListed(block, true); err != nil {
		// put the file back as it was: a block that tacctl.yaml does not name
		// is a block nobody sees
		if cur.exists {
			_ = st.Write(c.level, c.vendor, block, cur.text)
		} else {
			_ = st.Remove(c.level, c.vendor, block)
		}
		return inv.usageErr("tacctl.yaml could not be written: "+strings.Join(msgs(err), " "), "The block was not set.")
	}
	a.Audit().Raw("auth.info", "block-"+event+" name="+c.logName(block)+" bytes="+strconv.Itoa(len(text))+
		" objects="+strconv.Quote(blockCounts(bc.doc))+" by="+inv.sudoUser())
	a.Out.Info("The " + block + " block of " + c.what() + " is set (" + strconv.Itoa(len(text)) + " bytes) and in force.")
	inv.echo("  What the devices need: " + c.pullHint())
	return nil
}

// pullHint is how the devices this block reaches are brought up to date.
func (c *blockCtx) pullHint() string {
	if c.isDevice() {
		return "tacctl device config pull " + shellWord(c.dev.Name) + ", then tacctl device config plan " + shellWord(c.dev.Name) + "."
	}
	return "tacctl device config pull --scope " + c.level.Scope + ", then tacctl device config plan --scope " + c.level.Scope + "."
}

// --- remove -----------------------------------------------------------------------

func (c *blockCtx) remove(block string, p Parsed) error {
	inv := c.inv
	a := inv.app
	if err := c.requireSuperuser("remove"); err != nil {
		return err
	}
	f := c.file(block)
	if f.err != nil && !f.listed {
		return f.err
	}
	if !f.listed && !f.exists && f.err == nil {
		return inv.usageErr(upperFirst(c.what()) + " has no " + block + " block to remove.")
	}
	if err := inv.confWritable(); err != nil {
		return err
	}
	a.Out.Warn("About to remove the " + block + " block of " + c.what() + " (" + c.vendor + "), its file and its entry in tacctl.yaml.")
	inv.echo("  What the block set is no longer rendered: nothing is deleted from a device, and the next compare lists those statements as the device's own, kept (unmanaged).")
	inv.echo("  The snapshot taken first holds the block (it may hold community strings).")
	if !p.Has("-y") && !a.Prompter().ConfirmPrefix("  Confirm removal? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	if err := inv.snapshotFirst(); err != nil {
		return err
	}
	if err := c.setListed(block, false); err != nil {
		return inv.usageErr("tacctl.yaml could not be written: "+strings.Join(msgs(err), " "), "Nothing was changed.")
	}
	if err := c.store().Remove(c.level, c.vendor, block); err != nil && err != blocks.ErrNotFound {
		return err
	}
	a.Audit().Raw("auth.info", "block-remove name="+c.logName(block)+" by="+inv.sudoUser())
	a.Out.Info("The " + block + " block of " + c.what() + " is removed.")
	return nil
}

// blockName is the block a verb names, refused when the store does not know
// it.
func (inv *invocation) blockName(block string) error {
	if err := blocks.ValidateBlock(block); err != nil {
		return inv.usageErr(msgs(err)...)
	}
	return nil
}

// vendorWordOf is "a Junos" or "an IOS" for a block vendor.
func vendorWordOf(vendor string) string {
	if vendor == blocks.VendorCisco {
		return "an IOS or IOS-XE"
	}
	return "a Junos"
}
