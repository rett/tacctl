package ui

import (
	"io"
	"os"
	"sync"
)

// File returns the file behind w: w itself when it is an *os.File, or the
// file a stream made by Plain writes to. Terminal checks and the programs
// tacctl starts with w as their output ask for it, so that a stream with its
// colour taken out still reads as the terminal it is. ok is false when w is
// not a file.
func File(w io.Writer) (f *os.File, ok bool) {
	switch x := w.(type) {
	case *os.File:
		return x, x != nil
	case interface{ File() *os.File }:
		f = x.File()
		return f, f != nil
	}
	return nil, false
}

// Plain is StripSGR for a process's own stream: the sink is safe for
// concurrent use (an *os.File is, and the writers that replace one must be),
// and File gives back the file behind w when there is one. Closing it
// writes a sequence still held and leaves w open.
func Plain(w io.Writer) io.WriteCloser {
	return &plainStream{sink: StripSGR(w), w: w}
}

type plainStream struct {
	mu   sync.Mutex
	sink io.WriteCloser
	w    io.Writer
}

func (p *plainStream) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sink.Write(b)
}

func (p *plainStream) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sink.Close()
}

// File is the file the stream writes to (nil when it is not a file).
func (p *plainStream) File() *os.File {
	f, _ := File(p.w)
	return f
}
