package cidr

import (
	"bufio"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
)

// corpus.jsonl holds what Python 3.12's ipaddress.ip_network(s, strict=False)
// makes of each input (testdata/gen.py); every line must agree.
func TestCorpusAgainstPython(t *testing.T) {
	f, err := os.Open("testdata/corpus.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		var rec struct {
			In       string  `json:"in"`
			Canon    *string `json:"canon"`
			Key      *[3]any `json:"key"`
			Wildcard *string `json:"wildcard"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("line %d: %v", n+1, err)
		}
		n++
		got := Canonical(rec.In)
		if rec.Canon == nil {
			if got != "" {
				t.Errorf("Canonical(%q) = %q, Python rejects it", rec.In, got)
			}
			if err := Validate(rec.In); err == nil {
				t.Errorf("Validate(%q) accepted what Python rejects", rec.In)
			}
			if _, ok := SortKey(rec.In); ok {
				t.Errorf("SortKey(%q) ok for invalid input", rec.In)
			}
			if w := CiscoWildcard(rec.In); w != "" {
				t.Errorf("CiscoWildcard(%q) = %q for invalid input", rec.In, w)
			}
			continue
		}
		if got != *rec.Canon {
			t.Errorf("Canonical(%q) = %q, want %q", rec.In, got, *rec.Canon)
		}
		if err := Validate(rec.In); err != nil {
			t.Errorf("Validate(%q) = %v, Python accepts it", rec.In, err)
		}
		k, ok := SortKey(rec.In)
		if !ok {
			t.Errorf("SortKey(%q) not ok", rec.In)
			continue
		}
		bc, _ := new(big.Int).SetString(rec.Key[1].(string), 10)
		nw, _ := new(big.Int).SetString(rec.Key[2].(string), 10)
		if int(rec.Key[0].(float64)) != k.Version || bigOf(k.Broadcast).Cmp(bc) != 0 || bigOf(k.Network).Cmp(nw) != 0 {
			t.Errorf("SortKey(%q) = %+v, want %v", rec.In, k, rec.Key)
		}
		want := ""
		if rec.Wildcard != nil {
			want = *rec.Wildcard
		}
		if w := CiscoWildcard(rec.In); w != want {
			t.Errorf("CiscoWildcard(%q) = %q, want %q", rec.In, w, want)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 1000 {
		t.Fatalf("corpus has only %d cases", n)
	}
}

func bigOf(v [2]uint64) *big.Int {
	x := new(big.Int).SetUint64(v[0])
	x.Lsh(x, 64)
	return x.Or(x, new(big.Int).SetUint64(v[1]))
}

// --- tests/unit/cidr.bats: validate_cidr ---

func TestValidateAcceptsIPv4(t *testing.T) {
	for _, s := range []string{"10.0.0.0/8", "192.168.1.0/24", "10.1.5.5/32"} {
		if err := Validate(s); err != nil {
			t.Errorf("Validate(%q) = %v", s, err)
		}
	}
}

func TestValidateAcceptsIPv6(t *testing.T) {
	for _, s := range []string{"2001:db8::/32", "fe80::/10"} {
		if err := Validate(s); err != nil {
			t.Errorf("Validate(%q) = %v", s, err)
		}
	}
}

func TestValidateAcceptsHostBits(t *testing.T) {
	if err := Validate("10.1.5.5/24"); err != nil {
		t.Error(err)
	}
}

func TestValidateRejectsGarbage(t *testing.T) {
	for _, s := range []string{"not-a-cidr", "10.0.0.0/33", "999.0.0.0/8", ""} {
		err := Validate(s)
		var ie *InvalidError
		if !errors.As(err, &ie) {
			t.Errorf("Validate(%q) = %v, want *InvalidError", s, err)
			continue
		}
		if want := "Invalid CIDR: '" + s + "'"; err.Error() != want {
			t.Errorf("message = %q, want %q", err.Error(), want)
		}
	}
}

// --- canonicalize_cidr ---

func TestCanonical(t *testing.T) {
	for in, want := range map[string]string{
		"10.1.5.5/24":            "10.1.5.0/24",
		"172.16.1.99/16":         "172.16.0.0/16",
		"2001:DB8::/32":          "2001:db8::/32",
		"2001:0db8:0000::/48":    "2001:db8::/48",
		"10.0.0.0/8":             "10.0.0.0/8",
		"2001:db8::/32":          "2001:db8::/32",
		"not-a-cidr":             "",
		"":                       "",
		"10.0.0.1":               "10.0.0.1/32",
		"10.0.0.0/255.0.0.0":     "10.0.0.0/8",
		"10.0.0.0/0.255.255.255": "10.0.0.0/8",
	} {
		if got := Canonical(in); got != want {
			t.Errorf("Canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- cidr_to_cisco_wildcard ---

func TestCiscoWildcard(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.0/8":     "10.0.0.0 0.255.255.255",
		"192.168.1.0/24": "192.168.1.0 0.0.0.255",
		"10.1.2.3/32":    "10.1.2.3 0.0.0.0",
		"0.0.0.0/0":      "0.0.0.0 255.255.255.255",
		"2001:db8::/32":  "",
		"garbage":        "",
	} {
		if got := CiscoWildcard(in); got != want {
			t.Errorf("CiscoWildcard(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- parse_cidr_list ---

func TestParseList(t *testing.T) {
	got, err := ParseList("10.0.0.0/8, 192.168.1.5/24, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "192.168.1.0/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseListEmpty(t *testing.T) {
	for _, in := range []string{"", " ", ",", " , ,"} {
		got, err := ParseList(in)
		if err != nil || len(got) != 0 {
			t.Errorf("ParseList(%q) = %v, %v", in, got, err)
		}
	}
}

func TestParseListInvalid(t *testing.T) {
	_, err := ParseList("10.0.0.0/8, not-a-cidr")
	var ie *InvalidError
	if !errors.As(err, &ie) || ie.Value != "not-a-cidr" {
		t.Errorf("err = %v", err)
	}
}

func TestParseListDedupeOnCanonicalForm(t *testing.T) {
	got, err := ParseList("10.1.2.3/8,10.0.0.0/8,2001:DB8::1/32,2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"10.0.0.0/8", "2001:db8::/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

// The quirks the bash has: only the first line is read, and entries pass
// through xargs.
func TestParseListShellQuirks(t *testing.T) {
	got, err := ParseList("10.0.0.0/8\n192.168.0.0/16")
	if err != nil || !reflect.DeepEqual(got, []string{"10.0.0.0/8"}) {
		t.Errorf("multi-line: %v, %v", got, err)
	}
	got, err = ParseList(`"10.0.0.0/8", '10.1.0.0/16'`)
	if err != nil || !reflect.DeepEqual(got, []string{"10.0.0.0/8", "10.1.0.0/16"}) {
		t.Errorf("quoted: %v, %v", got, err)
	}
	_, err = ParseList("10.0.0.0/8 extra")
	var ie *InvalidError
	if !errors.As(err, &ie) || ie.Value != "10.0.0.0/8 extra" {
		t.Errorf("inner blanks: %v", err)
	}
	if _, err = ParseList(`"10.0.0.0/8`); !errors.Is(err, ErrUnmatchedQuote) {
		t.Errorf("unmatched quote: %v", err)
	}
}

// --- sort_cidrs_by_specificity ---

func TestSortIPv4BeforeIPv6(t *testing.T) {
	got := SortBySpecificity([]string{"2001:db8::/32", "10.0.0.0/8"})
	if want := []string{"10.0.0.0/8", "2001:db8::/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

// 10.0.0.0/8 and 10.0.0.0/24 share the network address; the /24's broadcast
// is the smaller number, so it sorts first.
func TestSortNarrowerFirstOnEqualNetwork(t *testing.T) {
	got := SortBySpecificity([]string{"10.0.0.0/8", "10.0.0.0/24"})
	if want := []string{"10.0.0.0/24", "10.0.0.0/8"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestSortDropsInvalidSilently(t *testing.T) {
	got := SortBySpecificity([]string{"10.0.0.0/8", "garbage", "", "  ", "192.168.0.0/16"})
	if want := []string{"10.0.0.0/8", "192.168.0.0/16"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

// The entries keep their own text (trimmed), duplicates stay, and equal keys
// keep input order, as Python's stable sorted() does.
func TestSortKeepsTextAndIsStable(t *testing.T) {
	got := SortBySpecificity([]string{" 10.0.0.5/24 ", "10.0.0.0/24", "10.0.0.5/24", "9.0.0.0/8"})
	if want := []string{"9.0.0.0/8", "10.0.0.5/24", "10.0.0.0/24", "10.0.0.5/24"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v", got)
	}
}

func TestSortKeyOrdering(t *testing.T) {
	var keys []Key
	for _, s := range []string{"10.0.0.0/24", "10.0.0.0/8", "::/0", "1.0.0.0/8"} {
		k, ok := SortKey(s)
		if !ok {
			t.Fatal(s)
		}
		keys = append(keys, k)
	}
	if !keys[0].Less(keys[1]) || keys[1].Less(keys[0]) || !keys[3].Less(keys[0]) || !keys[1].Less(keys[2]) {
		t.Errorf("ordering wrong: %+v", keys)
	}
}

func TestNetworkAccessors(t *testing.T) {
	n, err := Parse("10.1.5.5/24")
	if err != nil {
		t.Fatal(err)
	}
	if n.IsIPv6() || n.Version() != 4 || n.PrefixLen() != 24 || n.String() != "10.1.5.0/24" {
		t.Errorf("%+v", n)
	}
	n, _ = Parse("2001:db8::1/64")
	if !n.IsIPv6() || n.Version() != 6 || !strings.HasSuffix(n.String(), "/64") {
		t.Errorf("%+v", n)
	}
}
