// Package adapters parses public log formats into flat records.
package adapters

import "fmt"

// Record is one parsed line, before field mapping.
type Record map[string]string

// Adapter parses exactly one wire format.
//
// Parse returns a nil Record and a nil error to mean the line carries no
// event at all — a blank line, or a format-specific directive such as
// Zeek's #fields header. A non-nil error means the line could not be
// parsed.
type Adapter interface {
	Parse(line []byte) (Record, error)
}

// For returns the adapter for a format name used in config.
func For(format string) (Adapter, error) {
	switch format {
	case "syslog5424":
		return NewSyslog5424(), nil
	case "suricata-eve":
		return NewSuricataEVE(), nil
	case "zeek-conn":
		return NewZeekConn(), nil
	default:
		return nil, fmt.Errorf("unsupported format %q", format)
	}
}
