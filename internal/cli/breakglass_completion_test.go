package cli

import (
	"reflect"
	"slices"
	"testing"
)

// The completion of the break-glass family: its verbs from the tree, the
// held devices of 'release' from the bridge, the device names of 'hold' and
// the flags from the Specs.
func TestCompleteBreakglass(t *testing.T) {
	live := map[string]string{"held": "lab-sw\nrtr-2\n", "devices": "lab-sw\nprod-sw\nrtr-2\n"}
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"breakglass", ""}, []string{"hold", "list", "release"}},
		{[]string{"breakglass", "rel"}, []string{"release"}},
		{[]string{"breakglass", "release", ""}, []string{"lab-sw", "rtr-2"}},
		{[]string{"breakglass", "hold", ""}, []string{"lab-sw", "prod-sw", "rtr-2"}},
		{[]string{"breakglass", "hold", "lab-sw", "--"}, []string{"--reason"}},
		{[]string{"breakglass", "hold", "--"}, []string{"--reason"}},
		{[]string{"breakglass", "list", ""}, []string{"--json"}},
	} {
		got, _ := completeWords(t, live, c.words...)
		slices.Sort(got)
		want := slices.Clone(c.want)
		slices.Sort(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: %q, want %q", c.words, got, want)
		}
	}
}
