package model

import (
	"sort"
	"strconv"
)

// A port of the parts of Python's difflib (3.12) the equivalence check
// uses: SequenceMatcher with no junk function and autojunk on, and
// unified_diff with its defaults (3 lines of context, '\n' line ends, no
// dates). The output is byte for byte what difflib writes.

type match struct{ a, b, size int }

type opcode struct {
	tag            byte // 'r'eplace, 'd'elete, 'i'nsert, 'e'qual
	i1, i2, j1, j2 int
}

type sequenceMatcher struct {
	a, b []string
	b2j  map[string][]int
}

func newSequenceMatcher(a, b []string) *sequenceMatcher {
	m := &sequenceMatcher{a: a, b: b, b2j: map[string][]int{}}
	for i, elt := range b {
		m.b2j[elt] = append(m.b2j[elt], i)
	}
	// autojunk: in a sequence of 200 or more, an element that makes up
	// more than 1% of it (plus one) is "popular" and not indexed.
	if n := len(b); n >= 200 {
		ntest := n/100 + 1
		for elt, idxs := range m.b2j {
			if len(idxs) > ntest {
				delete(m.b2j, elt)
			}
		}
	}
	return m
}

// findLongestMatch is SequenceMatcher.find_longest_match (no junk, so the
// junk-extension passes never apply).
func (m *sequenceMatcher) findLongestMatch(alo, ahi, blo, bhi int) match {
	besti, bestj, bestsize := alo, blo, 0
	j2len := map[int]int{}
	for i := alo; i < ahi; i++ {
		newj2len := map[int]int{}
		for _, j := range m.b2j[m.a[i]] {
			if j < blo {
				continue
			}
			if j >= bhi {
				break
			}
			k := j2len[j-1] + 1
			newj2len[j] = k
			if k > bestsize {
				besti, bestj, bestsize = i-k+1, j-k+1, k
			}
		}
		j2len = newj2len
	}
	for besti > alo && bestj > blo && m.a[besti-1] == m.b[bestj-1] {
		besti, bestj, bestsize = besti-1, bestj-1, bestsize+1
	}
	for besti+bestsize < ahi && bestj+bestsize < bhi && m.a[besti+bestsize] == m.b[bestj+bestsize] {
		bestsize++
	}
	return match{besti, bestj, bestsize}
}

func (m *sequenceMatcher) matchingBlocks() []match {
	la, lb := len(m.a), len(m.b)
	queue := [][4]int{{0, la, 0, lb}}
	var blocks []match
	for len(queue) > 0 {
		q := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		alo, ahi, blo, bhi := q[0], q[1], q[2], q[3]
		x := m.findLongestMatch(alo, ahi, blo, bhi)
		if x.size > 0 {
			blocks = append(blocks, x)
			if alo < x.a && blo < x.b {
				queue = append(queue, [4]int{alo, x.a, blo, x.b})
			}
			if x.a+x.size < ahi && x.b+x.size < bhi {
				queue = append(queue, [4]int{x.a + x.size, ahi, x.b + x.size, bhi})
			}
		}
	}
	sort.Slice(blocks, func(i, j int) bool {
		if blocks[i].a != blocks[j].a {
			return blocks[i].a < blocks[j].a
		}
		if blocks[i].b != blocks[j].b {
			return blocks[i].b < blocks[j].b
		}
		return blocks[i].size < blocks[j].size
	})
	var out []match
	i1, j1, k1 := 0, 0, 0
	for _, x := range blocks {
		if i1+k1 == x.a && j1+k1 == x.b {
			k1 += x.size
			continue
		}
		if k1 > 0 {
			out = append(out, match{i1, j1, k1})
		}
		i1, j1, k1 = x.a, x.b, x.size
	}
	if k1 > 0 {
		out = append(out, match{i1, j1, k1})
	}
	return append(out, match{la, lb, 0})
}

func (m *sequenceMatcher) opcodes() []opcode {
	i, j := 0, 0
	var out []opcode
	for _, x := range m.matchingBlocks() {
		var tag byte
		switch {
		case i < x.a && j < x.b:
			tag = 'r'
		case i < x.a:
			tag = 'd'
		case j < x.b:
			tag = 'i'
		}
		if tag != 0 {
			out = append(out, opcode{tag, i, x.a, j, x.b})
		}
		i, j = x.a+x.size, x.b+x.size
		if x.size > 0 {
			out = append(out, opcode{'e', x.a, i, x.b, j})
		}
	}
	return out
}

// groupedOpcodes is get_grouped_opcodes(n).
func (m *sequenceMatcher) groupedOpcodes(n int) [][]opcode {
	codes := m.opcodes()
	if len(codes) == 0 {
		codes = []opcode{{'e', 0, 1, 0, 1}}
	}
	if c := &codes[0]; c.tag == 'e' {
		c.i1, c.j1 = max(c.i1, c.i2-n), max(c.j1, c.j2-n)
	}
	if c := &codes[len(codes)-1]; c.tag == 'e' {
		c.i2, c.j2 = min(c.i2, c.i1+n), min(c.j2, c.j1+n)
	}
	nn := n + n
	var groups [][]opcode
	var group []opcode
	for _, c := range codes {
		if c.tag == 'e' && c.i2-c.i1 > nn {
			group = append(group, opcode{'e', c.i1, min(c.i2, c.i1+n), c.j1, min(c.j2, c.j1+n)})
			groups = append(groups, group)
			group = nil
			c.i1, c.j1 = max(c.i1, c.i2-n), max(c.j1, c.j2-n)
		}
		group = append(group, c)
	}
	if len(group) > 0 && (len(group) != 1 || group[0].tag != 'e') {
		groups = append(groups, group)
	}
	return groups
}

// formatRangeUnified is _format_range_unified.
func formatRangeUnified(start, stop int) string {
	beginning, length := start+1, stop-start
	if length == 1 {
		return strconv.Itoa(beginning)
	}
	if length == 0 {
		beginning--
	}
	return strconv.Itoa(beginning) + "," + strconv.Itoa(length)
}

// unifiedDiff is difflib.unified_diff(a, b, fromfile, tofile): a and b are
// lines that keep their line ends (the last may have none); so does the
// result, whose lines are concatenated.
func unifiedDiff(a, b []string, fromfile, tofile string) string {
	var out []byte
	for gi, group := range newSequenceMatcher(a, b).groupedOpcodes(3) {
		if gi == 0 {
			out = append(out, "--- "+fromfile+"\n+++ "+tofile+"\n"...)
		}
		first, last := group[0], group[len(group)-1]
		out = append(out, "@@ -"+formatRangeUnified(first.i1, last.i2)+" +"+formatRangeUnified(first.j1, last.j2)+" @@\n"...)
		for _, c := range group {
			if c.tag == 'e' {
				for _, line := range a[c.i1:c.i2] {
					out = append(out, ' ')
					out = append(out, line...)
				}
				continue
			}
			if c.tag == 'r' || c.tag == 'd' {
				for _, line := range a[c.i1:c.i2] {
					out = append(out, '-')
					out = append(out, line...)
				}
			}
			if c.tag == 'r' || c.tag == 'i' {
				for _, line := range b[c.j1:c.j2] {
					out = append(out, '+')
					out = append(out, line...)
				}
			}
		}
	}
	return string(out)
}

// splitLinesKeepEnds is str.splitlines(keepends=True) for text whose only
// line break is '\n' (json.dumps output).
func splitLinesKeepEnds(s string) []string {
	var out []string
	for len(s) > 0 {
		i := 0
		for i < len(s) && s[i] != '\n' {
			i++
		}
		if i < len(s) {
			i++
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}
