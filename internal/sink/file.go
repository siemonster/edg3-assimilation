package sink

import (
	"encoding/json"
	"os"
)

// NewFile appends JSON lines to path, creating it with owner-only permissions.
func NewFile(path string) (Sink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &writerSink{encoder: json.NewEncoder(f), closer: f}, nil
}
