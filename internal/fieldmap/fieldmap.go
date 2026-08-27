// Package fieldmap turns a flat adapter record into a canonical event.
package fieldmap

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/schema"
	"gopkg.in/yaml.v3"
)

// Map describes how one source format maps onto the canonical event.
type Map struct {
	Schema   string            `yaml:"schema"`
	Format   string            `yaml:"format"`
	TSLayout string            `yaml:"ts_layout"`
	Fields   map[string]string `yaml:"fields"`
	Static   map[string]string `yaml:"static"`
	Severity map[string]int    `yaml:"severity"`
}

// Load reads a field map and checks it is usable.
func Load(path string) (Map, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Map{}, err
	}
	var m Map
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return Map{}, fmt.Errorf("%s: %w", path, err)
	}
	if m.Format == "" || len(m.Fields) == 0 {
		return Map{}, fmt.Errorf("%s: format and fields are required", path)
	}
	if m.TSLayout == "" {
		m.TSLayout = "rfc3339"
	}
	return m, nil
}

// Apply renames the record's keys, coerces the timestamp and severity, and
// keeps every unmapped key as an attribute.
func (m Map) Apply(rec map[string]string, raw []byte) (schema.Event, error) {
	if m.Schema != schema.CanonicalURN {
		return schema.Event{}, fmt.Errorf("map schema %q is not %s", m.Schema, schema.CanonicalURN)
	}
	digest := sha256.Sum256(raw)
	e := schema.Event{Schema: m.Schema, Source: m.Format, RawSHA256: hex.EncodeToString(digest[:]),
		Severity: 5, Attrs: map[string]string{}}
	mapped := map[string]bool{}
	for canonical, key := range m.Fields {
		value, ok := rec[key]
		if !ok {
			continue
		}
		mapped[key] = true
		switch canonical {
		case "ts":
			ts, err := m.parseTime(value)
			if err != nil {
				return schema.Event{}, err
			}
			e.TS = ts
		case "host":
			e.Host = value
		case "message":
			e.Message = value
		case "kind":
			e.Kind = value
		case "severity":
			e.Severity = m.severity(value)
		default:
			e.Attrs[canonical] = value
		}
	}
	for key, value := range m.Static {
		switch key {
		case "kind":
			e.Kind = value
		case "host":
			e.Host = value
		case "message":
			e.Message = value
		case "severity":
			e.Severity = m.severity(value)
		default:
			e.Attrs[key] = value
		}
	}
	if level, ok := rec["severity"]; ok && !mapped["severity"] {
		e.Severity = m.severity(level)
	}
	for key, value := range rec {
		if !mapped[key] {
			if _, taken := e.Attrs[key]; !taken {
				e.Attrs[key] = value
			}
		}
	}
	if len(e.Attrs) == 0 {
		e.Attrs = nil
	}
	return e, nil
}

func (m Map) parseTime(value string) (time.Time, error) {
	switch strings.ToLower(m.TSLayout) {
	case "rfc3339":
		return time.Parse(time.RFC3339, value)
	case "epoch":
		seconds, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("epoch timestamp %q: %w", value, err)
		}
		return time.Unix(int64(seconds), int64((seconds-float64(int64(seconds)))*1e9)).UTC(), nil
	default:
		return time.Parse(m.TSLayout, value)
	}
}

func (m Map) severity(value string) int {
	if level, ok := m.Severity[strings.ToLower(value)]; ok {
		return level
	}
	if level, err := strconv.Atoi(value); err == nil && level >= 0 && level <= 7 {
		return level
	}
	return 5
}
