package conf

// The limits of the stored reports of 0.2.26 (D326), in tacctl.yaml: the
// largest size of one report in bytes and the most reports one user keeps;
// 0 is no cap, and a user's own override (a field of the user record in
// store.yaml) wins over them. The keys are written only when set. A 0.2.25
// binary does not know them (Added0226, rollback.go).
const (
	// ReportsMaxSizeKey is reports.max_size, 0 to 1 GiB in bytes.
	ReportsMaxSizeKey = "reports.max_size"
	// ReportsMaxCountKey is reports.max_count, 0 to 100000.
	ReportsMaxCountKey = "reports.max_count"
)

// The defaults of the two keys, a test holds them equal to internal/reports.
const (
	ReportsMaxSizeDefault  = 10 << 20
	ReportsMaxCountDefault = 100
)
