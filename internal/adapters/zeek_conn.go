package adapters

import (
	"fmt"
	"strings"
)

type zeekConn struct{ fields []string }

// NewZeekConn returns an adapter for Zeek TSV logs. It is stateful: the
// #fields directive names the columns for every later line, so one instance
// handles one file.
func NewZeekConn() Adapter { return &zeekConn{} }

func (z *zeekConn) Parse(line []byte) (Record, error) {
	text := string(line)
	if strings.HasPrefix(text, "#") {
		if after, ok := strings.CutPrefix(text, "#fields\t"); ok {
			z.fields = strings.Split(after, "\t")
		}
		return nil, nil // directives carry no event
	}
	if text == "" {
		return nil, nil
	}
	if len(z.fields) == 0 {
		return nil, fmt.Errorf("data line before a #fields header")
	}
	values := strings.Split(text, "\t")
	if len(values) != len(z.fields) {
		return nil, fmt.Errorf("line has %d columns, header declares %d", len(values), len(z.fields))
	}
	rec := Record{}
	for i, name := range z.fields {
		if values[i] != "-" && values[i] != "(empty)" {
			rec[name] = values[i]
		}
	}
	return rec, nil
}
