package adapters

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

type suricataEVE struct{}

// NewSuricataEVE returns an adapter for Suricata EVE JSON lines.
func NewSuricataEVE() Adapter { return suricataEVE{} }

func (suricataEVE) Parse(line []byte) (Record, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return nil, nil // a blank line carries no event
	}
	var doc map[string]any
	if err := json.Unmarshal(line, &doc); err != nil {
		return nil, fmt.Errorf("line is not an EVE JSON object: %w", err)
	}
	rec := Record{}
	flatten("", doc, rec)
	if len(rec) == 0 {
		return nil, errors.New("EVE object is empty")
	}
	return rec, nil
}

// flatten writes scalars into rec, joining nested keys with a dot. Arrays are
// skipped: no field map consumes them and their order is not stable.
func flatten(prefix string, doc map[string]any, rec Record) {
	for key, value := range doc {
		full := key
		if prefix != "" {
			full = prefix + "." + key
		}
		switch typed := value.(type) {
		case map[string]any:
			flatten(full, typed, rec)
		case string:
			rec[full] = typed
		case bool:
			rec[full] = strconv.FormatBool(typed)
		case float64:
			rec[full] = strconv.FormatFloat(typed, 'f', -1, 64)
		}
	}
}
