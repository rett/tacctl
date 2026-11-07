package cli

// The limits of the stored reports (docs/plans/0.2.26-plan.md D326): the global
// settings reports.max_size and reports.max_count of tacctl.yaml ('config
// reports') and the per-user override that wins over them ('user
// reports-limit'). 0 is no cap. A value the schema would refuse (a hand-edited
// file) reads as the default, as the other settings do; 'config validate'
// reports it.

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/reports"
)

// globalReportLimits are the limits of the whole server: the settings, else the
// defaults of internal/reports.
func (inv *invocation) globalReportLimits() (maxSize int64, maxCount int) {
	maxSize, maxCount = reports.DefaultMaxSize, reports.DefaultMaxCount
	if n, err := strconv.ParseInt(inv.confGet(conf.ReportsMaxSizeKey, strconv.FormatInt(maxSize, 10)), 10, 64); err == nil && n >= 0 && n <= names.ReportMaxSizeCap {
		maxSize = n
	}
	if n, err := atoiIn(inv.confGet(conf.ReportsMaxCountKey, strconv.Itoa(maxCount)), 0, names.ReportMaxCountCap); err == nil {
		maxCount = n
	}
	return maxSize, maxCount
}
