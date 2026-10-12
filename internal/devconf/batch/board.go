package batch

import "time"

// Row is one job as a progress view shows it.
type Row struct {
	Name string
	// Text is the state in the words of D67: "queued", "running", "ok",
	// "ok, differs in aaa,snmp", "failed: <reason>", "interrupted" or
	// "not started".
	Text string
	// Settled is true once the job is done or skipped; Result is then its
	// result.
	Settled  bool
	Result   Result
	Started  time.Time
	Finished time.Time
}

// Duration is how long the job ran, by the clock the events carried; zero
// until it is done.
func (r Row) Duration() time.Duration {
	if r.Started.IsZero() || r.Finished.IsZero() {
		return 0
	}
	return r.Finished.Sub(r.Started)
}

// Board is a View that keeps one Row per job in the order of the list. A
// terminal view embeds it (or calls it first) and repaints Rows after each
// Update; the appended, line-per-event output of a non-terminal is the
// Row of the event's Index. It holds no terminal code and no clock: times
// are the ones in the events.
type Board struct {
	rows []Row
	sum  Summary
	done bool
}

// Begin queues every name.
func (b *Board) Begin(names []string) {
	b.rows = make([]Row, len(names))
	for i, n := range names {
		b.rows[i] = Row{Name: n, Text: "queued"}
	}
}

// Update applies one event to its row. An index outside the board is
// ignored.
func (b *Board) Update(e Event) {
	if e.Index < 0 || e.Index >= len(b.rows) {
		return
	}
	r := &b.rows[e.Index]
	switch e.Phase {
	case PhaseRunning:
		r.Text = "running"
		r.Started = e.At
	case PhaseDone:
		r.Text = e.Result.Text()
		r.Settled = true
		r.Result = e.Result
		r.Finished = e.At
	case PhaseSkipped:
		r.Text = e.Result.Text()
		r.Settled = true
		r.Result = e.Result
	}
}

// End keeps the summary.
func (b *Board) End(s Summary) {
	b.sum = s
	b.done = true
}

// Rows is a copy of the rows in the order of the list.
func (b *Board) Rows() []Row {
	return append([]Row(nil), b.rows...)
}

// Row is the row of one job.
func (b *Board) Row(i int) Row {
	return b.rows[i]
}

// Summary is the run's summary once End was called; the second result
// tells whether it was.
func (b *Board) Summary() (Summary, bool) {
	return b.sum, b.done
}
