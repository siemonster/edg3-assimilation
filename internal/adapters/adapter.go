// Package adapters parses public log formats into flat records.
package adapters

import "fmt"

// Record is one parsed line, before field mapping.
type Record map[string]string

// Adapter parses exactly one wire format.
type Adapter interface {
	Name() string
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
