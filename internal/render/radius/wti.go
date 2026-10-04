package radius

// wtiBand is one band of the WTI-Super mapping: the lowest privilege level
// of the band, the attribute value and the unit's name for that access
// level. The bands are those of the TACACS+ mapping and must equal
// wti_access_level_for_privlvl and wti_super_for_privlvl in
// lib/render_devices.sh (a test pins them together).
type wtiBand struct {
	floor int
	value int
	label string
}

var wtiSuperBands = []wtiBand{
	{15, 3, "Administrator"}, {10, 2, "SuperUser"}, {5, 1, "User"}, {0, 0, "ViewOnly"},
}

// WTISuper is wti_super: the WTI-Super value for a privilege level and the
// name the unit gives that access level. A level below every band is the
// lowest one.
func WTISuper(privLvl int) (value int, label string) {
	for _, b := range wtiSuperBands {
		if privLvl >= b.floor {
			return b.value, b.label
		}
	}
	last := wtiSuperBands[len(wtiSuperBands)-1]
	return last.value, last.label
}
