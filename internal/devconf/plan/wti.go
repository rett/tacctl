package plan

// The planner of a WTI console server (0.2.7, docs/plans/wti-interface.md
// sections 4 to 8). A unit has no configuration to paste: its settings are
// the items of numbered menu pages, a value is live when its Enter is
// accepted and the unit has no commit-confirm and no rollback. The plan is
// therefore a checklist of menu steps for a person to type (one per changed
// setting, ordered so that no step can take away the way in before the one
// that needs it), and for the IP tables list the one <iptables> block the
// page takes at its prompt: the only lines of an output that are not
// comments, and a block that is presented and never applied (the list is
// "forbidden remotely": it can lock out the management path).
//
// What is typed is decided by the ownership table (owned_wti.go): a
// single-valued setting is set to the rendered value (ModeSingle), the list
// is rewritten whole (ModeList), what the rendering does not set is the
// unit's own and stays. A finding the plan does not fix (a second host, a
// read/write community, the other protocol's page switched on, a local
// account nobody recorded) is listed with the step that would remove it.

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/wti"
	"github.com/rett/tacctl/internal/devices"
)

// WTIFacts are the facts of a unit's plan that neither the rendering nor
// the comparison say.
type WTIFacts struct {
	// Server is the address of the tacctl server, which the unit's IP tables
	// list must permit for tacctl's own queries ("" when it is not known).
	Server string
	// ListWhy is why the rendering holds no IP tables list although the
	// scope asks for one (the builder's unfilled value: the server's address
	// is not known), "" when it holds one or the scope asks for none.
	ListWhy string
	// OtherSessions is the number of other sessions the unit had at the pull
	// (nil: the record does not say).
	OtherSessions *int
}

// WTIStep is one step of a unit's checklist. Keys are the keys typed from
// the prompt ("/N 28 4"), Label the item as the unit prints it, Enter what
// to type at it, Was the value the pull showed. Back is what puts the old
// value back ("" when tacctl cannot say: BackNote then says what to do).
type WTIStep struct {
	// Line is the index into Delta.Lines (or Delta.Cleanup.Lines for a
	// cleanup step) of the step's Line.
	Line  int
	Keys  string
	Label string
	// Enter holds a secret's value when the step types one (--secrets);
	// EnterShown is Enter with the value left out.
	Enter, EnterShown string
	Was               string
	Back, BackNote    string
	// Key and Value are the statement the step makes true ("tacacs primary",
	// "192.0.2.42"); Clear says the step empties the item (Value is then
	// ""). Secret marks a step that types a secret.
	Key, Value string
	Clear      bool
	Secret     bool
	// Guarded marks a step that can take away the AAA path.
	Guarded bool
	Section string
}

// WTIBlock is the IP tables paste of a unit's plan.
type WTIBlock struct {
	// Line is the index into Delta.Lines of the paste's Line.
	Line int
	// Commands are the rendered entries, as the block pastes them
	// ("iptables -A INPUT -i lo -j ACCEPT"); Tail are the unit's own tail
	// entries the pull showed, kept as they are, after them.
	Commands, Tail []string
	// Old is the unit's list as the pull showed it, in order.
	Old []string
	// Restricts says the block ends in a rule that refuses what it does not
	// permit (the final DROP or an INPUT policy of DROP).
	Restricts bool
	// OldUnsafe are the entries of Old that the back-out cannot paste back
	// (a shape the paste check does not allow).
	OldUnsafe []string
}

// WTIPlan is what a unit's plan holds beside Delta.Lines.
type WTIPlan struct {
	// Proto is the protocol the rendering is for (tacacs or radius).
	Proto string
	// Steps are the checklist, in the order to do them.
	Steps []WTIStep
	// Block is the IP tables paste (nil: none).
	Block *WTIBlock
	// CleanupSteps are the steps of the --converge region.
	CleanupSteps []WTIStep
	// GuardedAAA says a step changes the AAA path (the check of the
	// walkthrough's Step 8 applies); SNMPSteps that one changes SNMP.
	GuardedAAA, SNMPSteps bool
}

// wtiForm is how an item takes its value.
type wtiForm int

const (
	wfPick wtiForm = iota
	wfNumber
	wfText
	wfAddr
	wfSecret
	wfCommunity
	wfLevel
	wfServices
)

// wtiItem is how a statement key is entered on its page.
type wtiItem struct {
	form wtiForm
	// picks are the page's choices in its order; numbered says the numbers
	// were seen on a unit (else the text is what is entered).
	picks    []string
	numbered bool
	// kind names the secret an item holds, for the sensitivity line.
	kind string
	// keys and label override the page tables' (the Default User Access
	// switch is item 1 of the page item 8 opens).
	keys, label string
}

var (
	wtiOffOn     = []string{"Off", "On"}
	wtiYesNo     = []string{"No", "Yes"}
	wtiFallback  = []string{"Off", "On (All failures)", "On (Transport failure)"}
	wtiModule    = []string{"Disabled", "Enabled"}
	wtiVersion   = []string{"V1/V2 Only", "V3", "All"}
	wtiLevelText = map[string]string{"viewonly": "View Only", "user": "User", "superuser": "SuperUser", "administrator": "Administrator"}
	wtiServText  = map[string]string{"serial": "Serial Port", "telnet-ssh": "Telnet/SSH", "web": "Web", "restful-api": "RESTful API"}
)

// wtiItems are the entry forms of the statements tacctl sets or clears.
// The pick numbers are those the screens of the 8.10 pages show
// (tests/fixtures/devconf/wti); a pick whose screen was not captured is
// entered by its text.
var wtiItems = map[string]wtiItem{
	"tacacs enable":           {form: wfPick, picks: wtiOffOn, numbered: true},
	"tacacs primary":          {form: wfAddr},
	"tacacs secondary":        {form: wfAddr},
	"tacacs secret":           {form: wfSecret, kind: "TACACS+ SECRET"},
	"tacacs fallback-timer":   {form: wfNumber},
	"tacacs fallback-local":   {form: wfPick, picks: wtiFallback, numbered: true},
	"tacacs port":             {form: wfNumber},
	"tacacs default-access":   {form: wfPick, picks: wtiOffOn, keys: "/N 28 8 1", label: "Default User Access"},
	"tacacs default-level":    {form: wfLevel},
	"tacacs default-services": {form: wfServices},
	"tacacs account-module":   {form: wfPick, picks: wtiModule, numbered: true},
	"tacacs session-module":   {form: wfPick, picks: wtiModule, numbered: true},
	"tacacs service-name":     {form: wfText},
	"tacacs debug":            {form: wfPick, picks: wtiOffOn, numbered: true},

	"radius enable":          {form: wfPick, picks: wtiOffOn, numbered: true},
	"radius primary":         {form: wfAddr},
	"radius secondary":       {form: wfAddr},
	"radius primary-secret":  {form: wfSecret, kind: "RADIUS SECRET"},
	"radius fallback-timer":  {form: wfNumber},
	"radius fallback-local":  {form: wfPick, picks: wtiFallback, numbered: true},
	"radius retries":         {form: wfNumber},
	"radius port":            {form: wfNumber},
	"radius accounting-port": {form: wfNumber},
	"radius default-access":  {form: wfPick, picks: wtiOffOn, keys: "/N 29 11 1", label: "Default User Access"},
	"radius onetime-auth":    {form: wfPick, picks: wtiOffOn, numbered: true},
	"radius debug":           {form: wfPick, picks: wtiOffOn, numbered: true},

	"snmp enable":       {form: wfPick, picks: wtiOffOn, numbered: true},
	"snmp version":      {form: wfPick, picks: wtiVersion, numbered: true},
	"snmp read-only":    {form: wfPick, picks: wtiYesNo},
	"snmp contact":      {form: wfText},
	"snmp location":     {form: wfText},
	"snmp ro-community": {form: wfCommunity, kind: "SNMP COMMUNITY"},
	"snmp rw-community": {form: wfCommunity, kind: "SNMP COMMUNITY"},
}

// wtiStepOrder is the order of the steps within a section: the lock-out
// safe order of the design (the secret first, then where it is sent, then
// what the unit does with the answer, the switch that turns the protocol on
// last), and the SNMP page with its switch last.
var wtiStepOrder = []string{
	"snmp version", "snmp read-only", "snmp contact", "snmp location", "snmp ro-community", "snmp enable",
	"tacacs secret", "tacacs primary", "tacacs port", "tacacs service-name",
	"tacacs default-access", "tacacs default-level", "tacacs default-services",
	"tacacs account-module", "tacacs session-module", "tacacs fallback-timer", "tacacs fallback-local",
	"tacacs debug", "tacacs enable",
	"radius primary-secret", "radius primary", "radius port", "radius accounting-port", "radius retries",
	"radius default-access", "radius onetime-auth", "radius fallback-timer", "radius fallback-local",
	"radius debug", "radius enable",
}

// wtiLocation resolves an item's keys and label: the override of the entry
// form, else the page tables'.
func wtiLocation(key string, it wtiItem) (keys, label string, guarded bool, ok bool) {
	for _, p := range wti.Pages {
		if p.Kind == wti.KindPrompt {
			continue // a read-only page of the same item, never typed at
		}
		for _, pi := range p.Items {
			if pi.Key != key {
				continue
			}
			keys = strings.ReplaceAll(p.Path, " > ", " ") + " " + strconv.Itoa(pi.Number)
			label = pi.Label
			guarded = pi.Risk == wti.RiskGuarded
			if it.keys != "" {
				keys = it.keys
			}
			if it.label != "" {
				label = it.label
			}
			return keys, label, guarded, true
		}
	}
	return "", "", false, false
}

// wtiPlaceholder names the command that shows a secret's value.
func wtiPlaceholder(kind, scope string) string {
	if kind == "SNMP COMMUNITY" {
		return "<the scope's SNMP community: tacctl scope snmp " + scope + " show --reveal>"
	}
	return "<the scope's " + strings.TrimSuffix(kind, " SECRET") + " secret: tacctl scope secret show " + scope + ">"
}

// wtiKeyOf is the item a statement is about: its key words, a user's name
// and key, the list for an IP tables entry.
func wtiKeyOf(stem string) string {
	c := wti.ParseLine(stem)
	switch c.Form {
	case wti.FormUnknown:
		f := strings.Fields(stem)
		if len(f) > 2 {
			f = f[:2]
		}
		return strings.Join(f, " ")
	case wti.FormUser:
		return "user " + c.Name + " " + c.Key
	}
	return c.Key
}

// wtiValueOf is the value of a statement as the comparison shows it.
func wtiValueOf(stem string) string { return wti.ParseLine(stem).Value }

// the shapes of a command the unit's list may be pasted with: printable
// ASCII, 256 characters at most (the page's own limit).
var reWTICommand = regexp.MustCompile(`^iptables -[AP] [ -~]{1,244}$`)

// wtiSafeText reports a value that can be typed at a prompt as it stands:
// printable ASCII, no blank at either end.
func wtiSafeText(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// wtiTypeable checks a value against what its prompt accepts (the pages'
// own lists of characters); "" is typeable.
func wtiTypeable(it wtiItem, v string) string {
	if !wtiSafeText(v) {
		return "the value holds a character that cannot be typed as it stands (printable ASCII only, no blank at either end)"
	}
	switch it.form {
	case wfSecret, wfCommunity:
		if len(v) > 64 || strings.ContainsAny(v, "#<>| ") {
			return "the value holds a character the secret prompt does not take (# < > | or a blank) or is longer than 64"
		}
	case wfAddr:
		if len(v) > 64 || strings.ContainsAny(v, " \"/\\*+<>&|") {
			return "the value holds a character the address prompt does not take or is longer than 64"
		}
	case wfText:
		if len(v) > 64 {
			return "the value is longer than 64 characters"
		}
	}
	return ""
}

// pickIndex is the 1-based number of the pick that reads as the canonical
// value, 0 when none does.
func pickIndex(picks []string, v string) int {
	for i, p := range picks {
		if wtiSlug(p) == v {
			return i + 1
		}
	}
	return 0
}

// wtiSlug is a pick's printed text as the canonical word.
func wtiSlug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
		default:
			dash = true
		}
	}
	return b.String()
}

// wtiEnterText is what is typed at an item for a canonical value.
func (it wtiItem) enterText(v string) string {
	switch it.form {
	case wfPick:
		if i := pickIndex(it.picks, v); i > 0 {
			if it.numbered {
				return fmt.Sprintf("%d (%s)", i, it.picks[i-1])
			}
			return it.picks[i-1]
		}
	case wfAddr:
		if strings.Contains(v, ":") {
			return "2 (IPv6), then " + v
		}
		return "1 (IPv4), then " + v
	case wfLevel:
		if t, ok := wtiLevelText[v]; ok {
			return t
		}
	case wfServices:
		var on []string
		for _, s := range strings.Split(v, ",") {
			t := wtiServText[s]
			if t == "" {
				t = s
			}
			on = append(on, t)
		}
		return "turn on: " + strings.Join(on, ", ")
	}
	return v
}

// valueText is a canonical value as the unit's page prints it, without a
// pick's number.
func (it wtiItem) valueText(v string) string {
	switch it.form {
	case wfPick:
		if i := pickIndex(it.picks, v); i > 0 {
			return it.picks[i-1]
		}
	case wfLevel:
		if t, ok := wtiLevelText[v]; ok {
			return t
		}
	}
	return v
}

// wasText is the value the pull showed, in the words of the unit's page.
func (it wtiItem) wasText(v string) string {
	switch {
	case v == "":
		return "(undefined)"
	case v == "<secret>":
		return "(defined)"
	case wti.IsLabel(v):
		return "(another string)"
	}
	switch it.form {
	case wfPick:
		if i := pickIndex(it.picks, v); i > 0 {
			if it.numbered {
				return fmt.Sprintf("%d (%s)", i, it.picks[i-1])
			}
			return it.picks[i-1]
		}
	case wfLevel:
		if t, ok := wtiLevelText[v]; ok {
			return t
		}
	case wfServices:
		var on []string
		for _, s := range strings.Split(v, ",") {
			t := wtiServText[s]
			if t == "" {
				t = s
			}
			on = append(on, t)
		}
		return strings.Join(on, ", ")
	}
	return v
}

// wtiClearText is what empties an item.
func (it wtiItem) clearText() string {
	if it.form == wfAddr {
		return "1 (IPv4), then <SPACE><CR>"
	}
	return "<SPACE><CR>"
}

// canClear reports an item that is emptied by a single space.
func (it wtiItem) canClear() bool {
	switch it.form {
	case wfAddr, wfText, wfSecret, wfCommunity:
		return true
	}
	return false
}

// wtiSpec is a step before it is a Line.
type wtiSpec struct {
	id      int
	section string
	rank    int
	step    WTIStep
	forStem []string
}

// wtiEntry is one finding of the comparison on its way to an Item.
type wtiEntry struct {
	section string
	kind    string
	stem    string
	words   string
	stems   []string
	// spec is the index into specs of the step that fixes it, -1 when none;
	// paste says the IP tables paste does.
	spec  int
	paste bool
	// why is why the plan does not fix a statement it could have.
	why    string
	remove []Line
	guard  string
	// group folds findings of one object into one item (groupWords says
	// what it is).
	group, groupWords string
}

// wtiPlanner is the state of one unit's plan.
type wtiPlanner struct {
	opt     Options
	d       *Delta
	exp     map[string]devices.Section
	cur     devconf.Extracted
	byName  map[string]devconf.SectionResult
	proto   string
	raw     map[string]string
	specs   []wtiSpec
	entries []wtiEntry
	block   *WTIBlock
	// aclStems are the compared statements the paste answers.
	aclStems []string
	present  int
	// the entries --converge may remove: the read/write community (-1 when
	// there is none) and the switches of the other protocol's page
	rw       int
	inactive []int
	// itemOf maps an entry to the item that reports it
	itemOf map[int]int
}

// wtiProtoOf is the protocol the rendering is for.
func wtiProtoOf(exp devices.Section) string {
	t, r := false, false
	for _, l := range exp.Lines {
		switch {
		case strings.HasPrefix(l, "tacacs "):
			t = true
		case strings.HasPrefix(l, "radius "):
			r = true
		}
	}
	switch {
	case t && !r:
		return "tacacs"
	case r && !t:
		return "radius"
	}
	return ""
}

// wtiMarkTail returns, per entry, whether it is part of the list's tail (a
// policy anywhere; the final DROP and the unit's OUTPUT ACCEPT where only
// tail entries follow them), as the comparison reads it.
func wtiMarkTail(cmds []string) []bool {
	out := make([]bool, len(cmds))
	open := true
	for i := len(cmds) - 1; i >= 0; i-- {
		c := strings.TrimPrefix(cmds[i], "iptables ")
		switch {
		case wti.IsPolicy(c):
			out[i] = true
		case wti.IsTailRule(c) && open:
			out[i] = true
		default:
			open = false
		}
	}
	return out
}

// the limit of the unit's IP tables page.
const wtiListLimit = 48

// planWTI is Plan for a WTI unit.
func planWTI(expected []devices.Section, current devconf.Extracted, opt Options) (Delta, error) {
	for _, s := range opt.Sections {
		if s == devconf.SectionRoles || s == devconf.SectionSystem {
			return Delta{}, fmt.Errorf("%w: a WTI unit has no %s section (it has aaa, snmp and mgmt-acl)", ErrUsage, s)
		}
	}
	results, err := devconf.CompareAll(expected, current)
	if err != nil {
		return Delta{}, err
	}
	d := Delta{Vendor: devconf.FamilyWTI, Scope: opt.Scope, BreakglassHeld: opt.BreakglassHeld}
	p := &wtiPlanner{opt: opt, d: &d, cur: current, exp: map[string]devices.Section{}, byName: map[string]devconf.SectionResult{},
		raw: map[string]string{}, rw: -1, itemOf: map[int]int{}}
	for _, s := range expected {
		p.exp[s.Name] = s
	}
	for _, r := range results {
		p.byName[r.Name] = r
	}
	p.proto = wtiProtoOf(p.exp[devconf.SectionAAA])
	for _, name := range []string{devconf.SectionAAA, devconf.SectionSNMP} {
		for _, l := range p.exp[name].Lines {
			l = strings.TrimSpace(l)
			c := wti.ParseLine(l)
			if c.Key == "" || c.Form == wti.FormUnknown {
				continue
			}
			if c.Form == wti.FormSecret {
				p.raw[c.Key] = strings.TrimSpace(strings.TrimPrefix(l, c.Key))
			} else {
				p.raw[c.Key] = c.Value
			}
		}
	}
	d.WTI = &WTIPlan{Proto: p.proto}

	for _, name := range PlanOrder(devconf.FamilyWTI) {
		r := p.byName[name]
		for _, n := range r.Notes {
			switch {
			case n == devconf.NoteWTINoTail:
				// said with the IP tables guards
			case !slices.Contains(d.Notes, n):
				d.Notes = append(d.Notes, n)
			}
		}
		sp := SectionPlan{Name: name}
		switch {
		case len(opt.Sections) > 0 && !slices.Contains(opt.Sections, name):
			sp.State = StateNotSelected
		case opt.Writable != nil && !opt.Writable[name]:
			sp.State, sp.Why, sp.Kind = StateSkipped, "not writable by the caller", KindNotWritable
			d.Skipped = append(d.Skipped, Skip{name, KindNotWritable, sp.Why})
		case name == devconf.SectionSNMP && slices.Contains(r.Notes, devconf.NoteWTIv3):
			sp.State, sp.Kind = StateSkipped, KindNotPlannable
			sp.Why = "the SNMP v3 users of a unit are not read, so this section is not compared and tacctl types none of it: the walkthrough's SNMP step is the procedure (tacctl device config show " + deviceWord(opt.Device) + ")"
			d.Skipped = append(d.Skipped, Skip{name, KindNotPlannable, sp.Why})
			d.Warnings = appendNew(d.Warnings, sp.Why)
		case name == devconf.SectionMgmtACL:
			p.acl(&sp, r)
		case r.State == devconf.StateNA:
			sp.State = StateNA
		default:
			p.settings(&sp, r)
		}
		d.Sections = append(d.Sections, sp)
	}
	// what the unit holds beside the rendering and the standard leaves to it
	// (the tail of its list is noted with the list's guards)
	for _, name := range []string{devconf.SectionAAA, devconf.SectionSNMP} {
		if r := p.byName[name]; r.Unmanaged > 0 {
			if st := d.Of(name).State; st == StatePlanned || st == StateNoChange {
				d.Notes = append(d.Notes, name+": "+r.UnmanagedNote())
			}
		}
	}
	d.Sections = append(d.Sections, SectionPlan{Name: devconf.SectionBreakGlass, State: StateNever})
	p.breakglass()
	p.assemble()
	p.items()
	if opt.Converge {
		p.cleanup()
	}
	p.finish()
	return d, nil
}

// deviceWord is a device's name for a command text, '<name>' when unknown.
func deviceWord(name string) string {
	if name == "" {
		return "<name>"
	}
	return name
}

// keyState is what the comparison says of one item.
type keyState struct {
	key        string
	miss       string
	extras     []string
	same       string
	sameSecret bool
}

// keyStates groups the lines of a section's comparison by item, in order of
// appearance.
func keyStates(r devconf.SectionResult) []*keyState {
	var out []*keyState
	idx := map[string]*keyState{}
	get := func(k string) *keyState {
		if s, ok := idx[k]; ok {
			return s
		}
		s := &keyState{key: k}
		idx[k] = s
		out = append(out, s)
		return s
	}
	for _, l := range r.Lines {
		stem := stemOf(l)
		switch l.Op {
		case devconf.OpMissing:
			get(wtiKeyOf(stem)).miss = stem
		case devconf.OpExtra:
			if l.Unmanaged {
				continue
			}
			s := get(wtiKeyOf(stem))
			s.extras = append(s.extras, stem)
		case devconf.OpSame:
			s := get(wtiKeyOf(stem))
			s.same, s.sameSecret = stem, l.Secret
		}
	}
	return out
}

// settings plans an aaa or snmp section: one step per setting whose
// rendered value the unit does not have, the unit's other statements kept.
func (p *wtiPlanner) settings(sp *SectionPlan, r devconf.SectionResult) {
	name := sp.Name
	fixed := 0
	for _, ks := range keyStates(r) {
		switch {
		case ks.miss != "":
			it, ok := wtiItems[ks.key]
			keys, label, guarded, located := wtiLocation(ks.key, it)
			if !ok || !located {
				p.entries = append(p.entries, wtiEntry{section: name, kind: KindMissing, stem: ks.miss, stems: []string{ks.miss}, spec: -1,
					why: "tacctl has no menu step for it"})
				continue
			}
			if p.step(name, ks, it, keys, label, guarded, false) {
				fixed++
			}
		case len(ks.extras) > 0:
			p.extra(name, ks)
		case ks.same != "" && p.opt.Secrets && ks.sameSecret:
			if it, ok := wtiItems[ks.key]; ok && it.form == wfSecret {
				if keys, label, guarded, located := wtiLocation(ks.key, it); located && p.step(name, ks, it, keys, label, guarded, true) {
					fixed++
					continue
				}
			}
			p.present++
		case ks.same != "" && ks.sameSecret:
			p.present++
		}
	}
	switch {
	case fixed > 0:
		sp.State, sp.Statements = StatePlanned, fixed
	default:
		sp.State = StateNoChange
	}
}

// step makes the step that gives an item its rendered value. It returns
// false when the item cannot be typed (the finding is recorded with why).
func (p *wtiPlanner) step(section string, ks *keyState, it wtiItem, keys, label string, guarded, rotate bool) bool {
	stem := ks.miss
	if rotate {
		stem = ks.same
	}
	stems := []string{stem}
	stems = append(stems, ks.extras...)
	kind := KindMissing
	if len(ks.extras) > 0 {
		kind = KindDifferent
	}
	refuse := func(why string) bool {
		p.entries = append(p.entries, wtiEntry{section: section, kind: kind, stem: stem, stems: stems, spec: -1, why: why})
		return false
	}
	secret := it.form == wfSecret || it.form == wfCommunity
	value := wtiValueOf(stem)
	typed := value
	if secret {
		typed = p.raw[ks.key]
		if typed == "" {
			return refuse("the scope holds no value for it")
		}
	}
	switch it.form {
	case wfAddr, wfText, wfSecret, wfCommunity, wfNumber:
		if why := wtiTypeable(it, typed); why != "" {
			return refuse(why)
		}
	}
	if it.form == wfPick && pickIndex(it.picks, value) == 0 {
		return refuse("tacctl does not know the unit's choice '" + value + "' for it")
	}
	wasV := ""
	if len(ks.extras) > 0 {
		wasV = wtiValueOf(ks.extras[0])
	}
	if rotate {
		wasV = wti.SecretMark
	}
	st := WTIStep{Keys: keys, Label: label, Key: ks.key, Value: value, Section: section, Guarded: guarded, Secret: secret}
	st.Was = it.wasText(wasV)
	switch {
	case secret:
		st.EnterShown = wtiPlaceholder(it.kind, p.opt.Scope)
		st.Enter = st.EnterShown
		if p.opt.Secrets {
			st.Enter = typed
		}
		st.Value = wti.SecretMark
	default:
		st.Enter = it.enterText(value)
		st.EnterShown = st.Enter
	}
	// what puts it back
	switch {
	case wasV == "" && it.canClear():
		st.Back = it.clearText()
	case wasV == "":
		st.BackNote = "no typed undo: the pull showed no value"
	case wasV == wti.SecretMark && it.form == wfCommunity, wti.IsLabel(wasV) && it.form == wfCommunity:
		st.BackNote = "re-enter the community you keep"
	case wasV == wti.SecretMark, wti.IsLabel(wasV):
		st.BackNote = "re-enter the secret you keep"
	case strings.HasSuffix(wasV, "...") && len(wasV) > 3:
		st.BackNote = "type the original text again (the unit's menu showed only: " + wasV + ")"
	default:
		st.Back = it.enterText(wasV)
	}
	p.specs = append(p.specs, wtiSpec{id: len(p.specs), section: section, rank: stepRank(ks.key), step: st, forStem: stems})
	p.entries = append(p.entries, wtiEntry{section: section, kind: kind, stem: stem, stems: stems, spec: len(p.specs) - 1})
	return true
}

func stepRank(key string) int {
	if i := slices.Index(wtiStepOrder, key); i >= 0 {
		return i
	}
	return len(wtiStepOrder)
}

// clearLine is the step that empties an item, as the report names it.
func clearLine(it wtiItem, keys, label string) Line {
	return Line{Op: OpStep, Text: keys + " (" + label + "), then " + it.clearText()}
}

// extra records the statements of the unit that the rendering does not
// have, with what removes them: left alone, as the ownership table says.
func (p *wtiPlanner) extra(section string, ks *keyState) {
	for _, stem := range ks.extras {
		e := wtiEntry{section: section, kind: KindExtra, stem: stem, stems: []string{stem}, spec: -1}
		isEnable := false
		if WTIRowID(section, stem, p.proto) == "wti.aaa.inactive-protocol" {
			// the other protocol's page, switched on: one finding, and the
			// one step that turns it off
			proto, _, _ := strings.Cut(stem, " ")
			e.group = "page " + proto
			e.groupWords = "the unit's " + wtiProtoWord(proto) + " page is in use while the scope uses " + wtiProtoWord(p.proto)
			if en, ok := wtiItems[proto+" enable"]; ok {
				if keys, label, _, located := wtiLocation(proto+" enable", en); located {
					e.remove = []Line{{Op: OpStep, Text: keys + " (" + label + ") -> " + en.enterText("off")}}
				}
			}
			isEnable = stem == proto+" enable on"
		} else {
			it, ok := wtiItems[ks.key]
			keys, label, _, located := wtiLocation(ks.key, it)
			if ok && located && it.canClear() {
				e.remove = []Line{clearLine(it, keys, label)}
			} else {
				e.guard = "tacctl has no step that removes it"
			}
		}
		p.entries = append(p.entries, e)
		switch {
		case isEnable:
			p.inactive = append(p.inactive, len(p.entries)-1)
		case ks.key == "snmp rw-community":
			p.rw = len(p.entries) - 1
		}
	}
}

func wtiProtoWord(p string) string {
	switch p {
	case "tacacs":
		return "TACACS+"
	case "radius":
		return "RADIUS"
	}
	return "its protocol"
}

// breakglass lists the findings of the local accounts: the plan types no
// account and no password, the walkthrough's Step 10 is the procedure.
func (p *wtiPlanner) breakglass() {
	r, ok := p.byName[devconf.SectionBreakGlass]
	if !ok || len(p.opt.Sections) > 0 {
		return
	}
	step10 := "the accounts are yours: the walkthrough's Step 10 lists them (tacctl device config show " + deviceWord(p.opt.Device) + "), and tacctl types no account and no password"
	for _, ks := range keyStates(r) {
		switch {
		case ks.miss != "":
			kind := KindMissing
			if len(ks.extras) > 0 {
				kind = KindDifferent
			}
			p.entries = append(p.entries, wtiEntry{section: devconf.SectionBreakGlass, kind: kind, stem: ks.miss,
				stems: append([]string{ks.miss}, ks.extras...), spec: -1, why: step10})
		default:
			for _, stem := range ks.extras {
				p.entries = append(p.entries, wtiEntry{section: devconf.SectionBreakGlass, kind: KindExtra, stem: stem, stems: []string{stem}, spec: -1,
					guard: "an account the scope does not record: tacctl never removes one; record it (tacctl scope breakglass " + p.scopeWord() + " add <name>) or delete it at /F 1 by hand"})
			}
		}
	}
}

func (p *wtiPlanner) scopeWord() string {
	if p.opt.Scope == "" {
		return "<scope>"
	}
	return p.opt.Scope
}

// acl plans the IP tables list: the whole rendered list, then the tail the
// unit has, in one block; refused by the guards below.
func (p *wtiPlanner) acl(sp *SectionPlan, r devconf.SectionResult) {
	exp := p.exp[devconf.SectionMgmtACL]
	cur := p.cur.Sections[devconf.SectionMgmtACL]
	d := p.d
	if len(exp.Lines) == 0 {
		if why := p.opt.WTI.ListWhy; why != "" {
			sp.State, sp.Kind = StateSkipped, KindRefused
			sp.Why = "the IP tables list cannot be built: " + why
			d.Skipped = append(d.Skipped, Skip{sp.Name, KindRefused, sp.Why})
			d.Warnings = appendNew(d.Warnings, sp.Why)
			return
		}
		sp.State = StateNA
		return
	}
	var cmds, old []string
	for _, l := range exp.Lines {
		if l = strings.TrimSpace(l); l != "" {
			cmds = append(cmds, l)
		}
	}
	for _, l := range cur.Lines {
		if l = strings.TrimSpace(l); l != "" {
			old = append(old, l)
		}
	}
	var tail []string
	for i, t := range wtiMarkTail(old) {
		if t {
			tail = append(tail, old[i])
		}
	}
	if slices.Contains(r.Notes, devconf.NoteWTINoTail) {
		d.Warnings = appendNew(d.Warnings, devconf.NoteWTINoTail)
	}
	if r.State != devconf.StateDiffers && r.State != devconf.StateMissing {
		sp.State = StateNoChange
		return
	}
	// the findings the paste answers
	var stems []string
	for _, l := range r.Lines {
		stem := stemOf(l)
		switch {
		case l.Op == devconf.OpMissing:
			stems = append(stems, stem)
			p.entries = append(p.entries, wtiEntry{section: sp.Name, kind: KindMissing, stem: stem, stems: []string{stem}, spec: -1, paste: true,
				group: "missing", groupWords: "entries of the standard's IP tables list that the unit does not have"})
		case l.Op == devconf.OpExtra && !l.Unmanaged:
			stems = append(stems, stem)
			p.entries = append(p.entries, wtiEntry{section: sp.Name, kind: KindExtra, stem: stem, stems: []string{stem}, spec: -1, paste: true,
				group: "extra", groupWords: "entries of the unit's list that are not in the standard's (the paste replaces the list: they are gone afterwards)"})
		case l.Op == devconf.OpOrder:
			stems = append(stems, l.Text)
			p.entries = append(p.entries, wtiEntry{section: sp.Name, kind: KindOrder, stem: "iptables: order differs", words: "the IP tables list is in another order than the standard's",
				stems: []string{l.Text}, spec: -1, paste: true})
		}
	}
	p.aclStems = stems

	// the guards: any of them refuses the section, and the rest still plans
	refuse := func(why string) {
		sp.State, sp.Kind, sp.Why = StateSkipped, KindRefused, why
		d.Skipped = append(d.Skipped, Skip{sp.Name, KindRefused, why})
		for i := range p.entries {
			if p.entries[i].section == sp.Name && p.entries[i].paste {
				p.entries[i].paste = false
				p.entries[i].why = firstSentence(why)
			}
		}
	}
	scope := p.scopeWord()
	switch n := len(cmds) + len(tail); {
	case n > wtiListLimit:
		refuse(fmt.Sprintf("the list would hold %d entries (%d rendered and %d of the unit's own tail) and the unit holds %d: reduce the scope's management permit list (tacctl scope mgmt-acl %s list) or its SNMP clients (tacctl scope snmp %s clients list), or use wider networks",
			n, len(cmds), len(tail), wtiListLimit, scope, scope))
		return
	}
	for _, c := range slices.Concat(cmds, tail) {
		if !reWTICommand.MatchString(c) {
			refuse("an entry of the list cannot be pasted as it stands (the paste takes printable ASCII commands of 256 characters at most, 'iptables -A' or 'iptables -P')")
			return
		}
	}
	if srv := p.opt.WTI.Server; srv != "" && !wtiPermits(cmds, srv) {
		refuse("the tacctl server " + srv + " is not permitted to reach the unit's ssh by the rendered list: the paste would cut tacctl off")
		return
	}
	restricts := slices.ContainsFunc(slices.Concat(cmds, tail), func(c string) bool {
		return c == "iptables -A INPUT -j DROP" || c == "iptables -P INPUT DROP"
	})
	if from := p.opt.From; from != "" {
		a, err := netip.ParseAddr(from)
		switch {
		case err != nil:
			refuse("--from " + from + " is not an address")
			return
		case a.Is6() && !a.Is4In6():
			d.Warnings = appendNew(d.Warnings, "--from "+from+" is an IPv6 address and the unit's list is IPv4 only: not checked; make sure you reach the unit from an address the list permits")
		case !wtiPermits(cmds, a.Unmap().String()):
			refuse("the IP tables list is replaced and " + from + " is not permitted to reach the unit's ssh by the rendered list: pasting it could cut you off")
			return
		}
	} else if restricts {
		d.Warnings = appendNew(d.Warnings, "the list ends with the final DROP, so from the paste on only the addresses it permits reach the unit and --from was not given: check that the address you are logged in from is permitted before you paste (--from <address> makes tacctl check)")
	}
	if n := p.opt.WTI.OtherSessions; n != nil && *n > 0 {
		d.Warnings = appendNew(d.Warnings, fmt.Sprintf("the pull saw %s on the unit: the paste is live for them too; type /SN before you paste and make sure no other administrator is working on it", plural(*n, "other session", "other sessions")))
	}
	if len(tail) == 0 {
		d.Warnings = appendNew(d.Warnings, devconf.NoteWTINoTail)
		if n := len(cmds) + len(wti.TailCommands()); n > wtiListLimit {
			d.Warnings = appendNew(d.Warnings, fmt.Sprintf("the list of the walkthrough's last step (the rules, then the DROP, the OUTPUT ACCEPT and the three policies) would hold %d entries and the unit holds %d", n, wtiListLimit))
		}
	}
	// A plain entry of the permit list (0.2.7) is every protocol and port from
	// its source, where a list of 0.2.6 and before rendered ssh and ping: the
	// paste widens what those sources reach, so the report says so.
	if plain := devices.WTIPlainPermits(cmds); len(plain) > 0 {
		verb := "allows"
		if len(plain) > 1 {
			verb = "allow"
		}
		d.Notes = appendNew(d.Notes, fmt.Sprintf("%s of the rendered list %s every protocol and port from the source (%s), the unit's telnet and web pages included: <cidr>:tcp/22 in the management permit list restricts a permit to ssh",
			plural(len(plain), "plain permit", "plain permits"), verb, strings.Join(plain, ", ")))
	}
	b := &WTIBlock{Commands: cmds, Tail: tail, Old: old, Restricts: restricts}
	for _, c := range old {
		if !reWTICommand.MatchString(c) {
			b.OldUnsafe = append(b.OldUnsafe, c)
		}
	}
	p.block = b
	sp.State, sp.Statements = StatePlanned, len(cmds)+len(tail)
}

// wtiPortsHold22 reports whether a rule's protocol and --dport let tcp port 22
// through: no protocol (every protocol and port), tcp with no port, with 22
// or with a range 'a:b' that holds it.
func wtiPortsHold22(proto, dport string) bool {
	switch {
	case proto == "" && dport == "", proto == "tcp" && dport == "":
		return true
	case proto == "" || dport == "22":
		return dport == "22"
	}
	lo, hi, ok := strings.Cut(dport, ":")
	if !ok {
		return false
	}
	l, err1 := strconv.Atoi(lo)
	h, err2 := strconv.Atoi(hi)
	return err1 == nil && err2 == nil && l <= 22 && 22 <= h
}

// wtiPermits reports whether the commands let an address reach the unit's
// ssh: an INPUT rule that accepts a source containing it for tcp port 22 (the
// port alone, a range that holds it, every tcp port, or every protocol).
func wtiPermits(cmds []string, addr string) bool {
	addr = strings.TrimSuffix(addr, "/32")
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, c := range cmds {
		f := strings.Fields(c)
		if len(f) < 4 || f[1] != "-A" || f[2] != "INPUT" {
			continue
		}
		var src, proto, dport, target string
		for i := 3; i+1 < len(f); i++ {
			switch f[i] {
			case "-s":
				src = f[i+1]
			case "-p":
				proto = f[i+1]
			case "--dport":
				dport = f[i+1]
			case "-j":
				target = f[i+1]
			}
		}
		// a rule for every protocol and port (a plain permit entry, no -p), or
		// for tcp with no port, port 22 or a range that holds it
		if target != "ACCEPT" || src == "" || (proto != "" && proto != "tcp") || !wtiPortsHold22(proto, dport) {
			continue
		}
		if pf, err := netip.ParsePrefix(src); err == nil && pf.Contains(a) {
			return true
		}
		if ad, err := netip.ParseAddr(src); err == nil && ad.Unmap() == a {
			return true
		}
	}
	return false
}

// assemble turns the specs into Lines in the order of the checklist, and the
// block into its Line.
func (p *wtiPlanner) assemble() {
	d := p.d
	secIdx := func(s string) int { return slices.Index(PlanOrder(devconf.FamilyWTI), s) }
	slices.SortStableFunc(p.specs, func(a, b wtiSpec) int {
		if x := secIdx(a.section) - secIdx(b.section); x != 0 {
			return x
		}
		return a.rank - b.rank
	})
	pos := map[int]int{}
	for i, s := range p.specs {
		pos[s.id] = i
		st := s.step
		st.Line = len(d.Lines)
		l := Line{Op: OpStep, Section: s.section, Text: stepFlat(st, st.Enter), For: s.forStem, Secret: st.Secret}
		if st.Secret {
			l.Elided = stepFlat(st, st.EnterShown)
			l.HasValue = st.Enter != st.EnterShown
		}
		d.Lines = append(d.Lines, l)
		d.WTI.Steps = append(d.WTI.Steps, st)
		if st.Guarded && s.section == devconf.SectionAAA {
			d.WTI.GuardedAAA = true
		}
		if s.section == devconf.SectionSNMP {
			d.WTI.SNMPSteps = true
		}
		if l.HasValue {
			d.Counts.SecretsByValue++
			if k := wtiItems[st.Key].kind; k != "" && !slices.Contains(d.SecretKinds, k) {
				d.SecretKinds = append(d.SecretKinds, k)
			}
		} else if st.Secret {
			d.Counts.Placeholders++
		}
	}
	for i := range p.entries {
		if e := &p.entries[i]; e.spec >= 0 {
			e.spec = pos[e.spec]
		}
	}
	if p.block != nil {
		p.block.Line = len(d.Lines)
		d.Lines = append(d.Lines, Line{Op: OpPaste, Section: devconf.SectionMgmtACL, For: p.aclStems,
			Text: fmt.Sprintf("IP tables: replace the unit's %s with %s (%d rendered, %d of the unit's own tail kept)",
				plural(len(p.block.Old), "entry", "entries"), plural(len(p.block.Commands)+len(p.block.Tail), "entry", "entries"), len(p.block.Commands), len(p.block.Tail))})
		d.WTI.Block = p.block
	}
}

// stepFlat is a step as one line of Display.
func stepFlat(st WTIStep, enter string) string {
	s := st.Keys + " " + st.Label + " -> " + enter
	if st.Was != "" {
		s += " (was: " + st.Was + ")"
	}
	return s
}

// items builds the report's items, the extras and the kept list from the
// entries.
func (p *wtiPlanner) items() {
	d := p.d
	type groupAt struct{ at, n int }
	groups := map[string]*groupAt{}
	// the extras that are one object: kept once, with the step that removes it
	extraAt := map[string]int{}
	rank := map[string]int{devconf.SectionAAA: 0, devconf.SectionSNMP: 1, devconf.SectionMgmtACL: 2, devconf.SectionBreakGlass: 3}
	order := make([]int, len(p.entries))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return rank[p.entries[a].section] - rank[p.entries[b].section] })
	for _, ei := range order {
		e := p.entries[ei]
		it := Item{Kind: e.kind, Section: e.section, Statement: e.stem, Words: e.words,
			Severity: severityOf(devconf.FamilyWTI, e.section, e.stem, e.kind)}
		if e.kind == KindOrder {
			it.Severity = SevAccess
		}
		if it.Words == "" {
			it.Words = wtiWords(e.stem)
		}
		if it.Kind == KindDifferent && len(e.stems) > 1 {
			var ws []string
			for _, s := range e.stems[1:] {
				v := wtiValueOf(s)
				if wit, ok := wtiItems[wtiKeyOf(s)]; ok {
					v = wit.valueText(v)
				}
				if wti.IsLabel(v) {
					v = "another string"
				}
				ws = append(ws, v)
			}
			it.Words += " (the device has: " + strings.Join(ws, "; ") + ")"
		}
		switch {
		case e.spec >= 0:
			it.Lines, it.Fixed = []int{d.WTI.Steps[e.spec].Line}, true
		case e.paste:
			it.Lines, it.Fixed = []int{d.WTI.Block.Line}, true
		}
		switch {
		case it.Fixed && e.paste && e.kind == KindExtra:
			it.Action = "Fixed by the IP tables paste (it replaces every entry: this one is gone afterwards)."
		case it.Fixed && e.paste:
			it.Action = "Fixed by the IP tables paste."
		case it.Fixed:
			it.Action = "Fixed by step " + fmt.Sprint(e.spec+1) + "."
		case e.why != "":
			it.Action = "Not fixed: " + strings.TrimSuffix(e.why, ".") + "."
		case e.guard != "":
			it.Action = "Left alone (" + e.guard + ")."
		case len(e.remove) > 0:
			it.Action = "Left alone. To remove it later" + removeText(e.remove)
		default:
			it.Action = "Left alone."
		}
		if e.kind == KindExtra && !it.Fixed {
			k := e.section + "|" + e.stem
			if e.group != "" {
				k = e.section + "|" + e.group
			}
			if _, seen := extraAt[k]; !seen {
				extraAt[k] = len(d.Extras)
				d.Extras = append(d.Extras, Extra{Section: e.section, Text: e.stem, Remove: e.remove, Guard: e.guard})
				d.Kept = append(d.Kept, Kept{Section: e.section, Text: e.stem})
			}
		}
		if e.group != "" {
			k := e.section + "|" + e.group + "|" + fmt.Sprint(it.Fixed) + "|" + it.Action
			if g, ok := groups[k]; ok {
				gi := &d.Items[g.at]
				gi.Lines = append(gi.Lines, it.Lines...)
				g.n++
				p.itemOf[ei] = g.at
				continue
			}
			it.Words = e.groupWords
			it.Statement = "e.g. " + e.stem
			groups[k] = &groupAt{at: len(d.Items), n: 1}
		}
		p.itemOf[ei] = len(d.Items)
		d.Items = append(d.Items, it)
	}
	// a folded item says how many statements it holds
	for _, g := range groups {
		if g.n > 1 {
			noun := plural(g.n, "statement", "statements")
			if d.Items[g.at].Section == devconf.SectionMgmtACL {
				noun = plural(g.n, "entry", "entries")
			}
			d.Items[g.at].Words += ": " + noun
		}
	}
	for i := range d.Items {
		d.Items[i].N = i + 1
		slices.Sort(d.Items[i].Lines)
		d.Items[i].Lines = slices.Compact(d.Items[i].Lines)
	}
}

// wtiWords is a statement in the words of a technician.
func wtiWords(stem string) string {
	c := wti.ParseLine(stem)
	v := c.Value
	if it, ok := wtiItems[c.Key]; ok && c.Form != wti.FormCommand {
		v = it.valueText(v)
	}
	switch c.Form {
	case wti.FormCommand:
		return "the IP tables entry: iptables " + v
	case wti.FormUser:
		switch c.Key {
		case "level":
			return "the local account " + c.Name + " is at level " + v
		case "password":
			return "the local account " + c.Name + " has its password"
		}
		return "the local account " + c.Name + ": " + c.Key
	case wti.FormUnknown:
		return stem
	}
	proto, rest, _ := strings.Cut(c.Key, " ")
	pw := wtiProtoWord(proto)
	switch c.Key {
	case "tacacs enable", "radius enable":
		return pw + " is " + v
	case "tacacs primary", "radius primary":
		return "the " + pw + " primary host is " + v
	case "tacacs secondary", "radius secondary":
		return "the " + pw + " secondary host is " + v
	case "tacacs secret", "radius primary-secret":
		return "the " + pw + " secret word"
	case "tacacs fallback-timer", "radius fallback-timer":
		return "the " + pw + " fallback timer is " + v + " seconds"
	case "tacacs fallback-local", "radius fallback-local":
		return "Fallback Local (" + pw + ") is " + v
	case "tacacs port", "radius port":
		return "the " + pw + " authentication port is " + v
	case "tacacs default-access", "radius default-access":
		return "Default User Access (" + pw + ") is " + v
	case "tacacs default-level":
		return "the default access level (" + pw + ") is " + v
	case "tacacs default-services":
		return "the default services (" + pw + ") are " + v
	case "tacacs account-module":
		return "the Account Management Module is " + v
	case "tacacs session-module":
		return "the Session Management Module is " + v
	case "tacacs service-name":
		return "the " + pw + " service name is " + v
	case "snmp enable":
		return "SNMP access is " + v
	case "snmp version":
		return "the SNMP version is " + v
	case "snmp read-only":
		return "SNMP read only is " + v
	case "snmp ro-community":
		return "the SNMP read-only community"
	case "snmp rw-community":
		return "an SNMP read/write community"
	case "snmp contact", "snmp location":
		return "the SNMP " + strings.TrimPrefix(c.Key, "snmp ") + " is " + v
	}
	if proto == "tacacs" || proto == "radius" {
		return "the " + pw + " " + strings.ReplaceAll(rest, "-", " ") + " is " + v
	}
	return strings.TrimSpace(c.Key + " " + v)
}

// finish sets the counts the report reads.
func (p *wtiPlanner) finish() {
	d := p.d
	d.Counts.Kept = len(d.Kept)
	d.Counts.SecretsPresent = p.present
	slices.Sort(d.SecretKinds)
	if d.WTI.GuardedAAA {
		var ns []int
		for i, st := range d.WTI.Steps {
			if st.Guarded && st.Section == devconf.SectionAAA {
				ns = append(ns, i+1)
			}
		}
		d.Warnings = appendNew(d.Warnings, wtiGuardWarning(ns, p.proto))
	}
}

// cleanup makes the --converge region (D111) of a unit: it offers two
// removals only, the read/write community and the switch of the other
// protocol's page. Everything else the unit holds is its own or a person's
// (a second host, an account), and the report says how to remove it.
func (p *wtiPlanner) cleanup() {
	d := p.d
	d.Converge = true
	c := &d.Cleanup
	if !d.Empty() {
		c.Deferred = CleanupDeferred
		return
	}
	// the server must be in place: a missing standard setting that the plan
	// could not fix refuses the cleanup as a whole
	whole := ""
	for _, e := range p.entries {
		if e.section == devconf.SectionAAA && (e.kind == KindMissing || e.kind == KindDifferent) && e.spec < 0 && !e.paste {
			whole = "the standard's TACACS+ or RADIUS settings are not in place and this plan does not put them there (" + wtiWords(e.stem) + ")"
			break
		}
	}
	why := map[string]string{}
	for _, name := range []string{devconf.SectionAAA, devconf.SectionSNMP} {
		switch sp := d.Of(name); sp.State {
		case StateNotSelected:
			why[name] = "the section is not selected (--section)"
		case StateSkipped:
			why[name] = "this plan does not plan the section: " + firstSentence(sp.Why)
		case StateNA:
			why[name] = "the standard has nothing for this section"
		}
	}
	if whole != "" {
		c.Whole = whole
	}
	offered := map[int]bool{}
	var secs []string
	add := func(ei int, st WTIStep) {
		st.Line = len(c.Lines)
		c.Lines = append(c.Lines, Line{Op: OpStep, Section: p.entries[ei].section, Text: stepFlat(st, st.Enter), For: []string{p.entries[ei].stem}})
		d.WTI.CleanupSteps = append(d.WTI.CleanupSteps, st)
		offered[ei] = true
		if !slices.Contains(secs, p.entries[ei].section) {
			secs = append(secs, p.entries[ei].section)
		}
	}
	if whole == "" {
		if ei := p.rw; ei >= 0 && why[devconf.SectionSNMP] == "" {
			it := wtiItems["snmp rw-community"]
			if keys, label, _, ok := wtiLocation("snmp rw-community", it); ok {
				add(ei, WTIStep{Keys: keys, Label: label, Enter: it.clearText(), EnterShown: it.clearText(), Key: "snmp rw-community", Clear: true,
					Was: it.wasText("<other:1>"), BackNote: "re-enter the community you keep", Section: devconf.SectionSNMP})
			}
		}
		done := map[string]bool{}
		for _, ei := range p.inactive {
			proto, _, _ := strings.Cut(p.entries[ei].stem, " ")
			if why[devconf.SectionAAA] != "" || done[proto] {
				continue
			}
			it := wtiItems[proto+" enable"]
			keys, label, guarded, ok := wtiLocation(proto+" enable", it)
			if !ok {
				continue
			}
			done[proto] = true
			// the whole page goes with its switch: its statements are one finding
			for gi, g := range p.entries {
				if g.group == "page "+proto && g.kind == KindExtra {
					offered[gi] = true
				}
			}
			add(ei, WTIStep{Keys: keys, Label: label, Enter: it.enterText("off"), EnterShown: it.enterText("off"), Was: it.enterText("on"),
				Back: it.enterText("on"), Key: proto + " enable", Value: "off", Guarded: guarded, Section: devconf.SectionAAA})
		}
	}
	for _, name := range PlanOrder(devconf.FamilyWTI) {
		if slices.Contains(secs, name) {
			n := 0
			for _, st := range d.WTI.CleanupSteps {
				if st.Section == name {
					n++
				}
			}
			c.Sections = append(c.Sections, SectionPlan{Name: name, State: StatePlanned, Why: cleanupWhy(devconf.FamilyWTI, name), Statements: n})
		}
	}
	for ei, e := range p.entries {
		if e.kind != KindExtra || e.paste || offered[ei] {
			continue
		}
		reason := "a cleanup of a unit removes only the read/write community and the switch of the other protocol's page: the rest is yours to remove"
		if w := why[e.section]; w != "" {
			reason = w
		} else if whole != "" {
			reason = whole
		} else if e.guard != "" {
			reason = e.guard
		}
		if ei == p.rw || slices.Contains(p.inactive, ei) || e.group != "" || len(e.remove) > 0 || e.guard != "" {
			c.Left = append(c.Left, CleanupLeft{Section: e.section, Text: e.stem, Why: reason})
		}
	}
	// the items: which step removes each
	for ei := range offered {
		if i, ok := p.itemOf[ei]; ok {
			for n, st := range d.WTI.CleanupSteps {
				if st.Key == "snmp rw-community" && ei == p.rw || strings.HasPrefix(p.entries[ei].stem, strings.TrimSuffix(st.Key, " enable")+" ") && strings.HasSuffix(st.Key, " enable") {
					d.Items[i].Action = "Removed by the cleanup region, step " + fmt.Sprint(n+1) + "."
				}
			}
		}
	}
}

// wtiGuardWarning is the warning that goes with the steps that change what
// the unit asks of the server (the walkthrough's Step 8 is their check).
func wtiGuardWarning(steps []int, proto string) string {
	word, verb := "Step "+strings.TrimPrefix(lineNumbers(steps), "line "), "changes"
	if len(steps) > 1 {
		word, verb = "Steps "+strings.TrimPrefix(lineNumbers(steps), "lines "), "change"
	}
	return word + " " + verb + " what the unit asks of the " + wtiProtoWord(proto) + " server or how it answers when the server fails: a wrong secret word, " +
		"host, port or service name does not stop a login, it returns every login to the unit's Default User Access level, and Fallback Local decides " +
		"whether the unit's own accounts work when the server does not answer; keep the serial session open and do the check after the ESC step before anything else"
}
