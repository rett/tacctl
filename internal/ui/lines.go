package ui

// ErrorLines writes err the way the bash writes a failed validator: one
// "[ERROR] <line>" per message line. An error that carries its lines (a
// Lines() []string method, as names.Error does) prints each as its own
// error() call; any other error prints its text as one line. A nil error
// prints nothing.
func (o Output) ErrorLines(err error) {
	if err == nil {
		return
	}
	if l, ok := err.(interface{ Lines() []string }); ok {
		for _, s := range l.Lines() {
			o.Error(s)
		}
		return
	}
	o.Error(err.Error())
}
