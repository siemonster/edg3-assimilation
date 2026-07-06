// Package schema defines the canonical event every adapter normalises into.
package schema

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// CanonicalURN identifies this canonical event shape. Consumers pin it.
const CanonicalURN = "urn:edg3:assim:canon:v1:7f3c9ab2"

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Event is one normalised telemetry record.
type Event struct {
	Schema    string            `json:"schema"`
	TS        time.Time         `json:"ts"`
	Source    string            `json:"source"`
	Host      string            `json:"host,omitempty"`
	Kind      string            `json:"kind"`
	Severity  int               `json:"severity"`
	Message   string            `json:"message,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	RawSHA256 string            `json:"raw_sha256"`
}

// Validate reports whether the event is complete enough to publish.
func (e Event) Validate() error {
	switch {
	case e.Schema != CanonicalURN:
		return fmt.Errorf("schema %q is not %s", e.Schema, CanonicalURN)
	case e.TS.IsZero():
		return errors.New("timestamp is missing")
	case e.Source == "":
		return errors.New("source is missing")
	case e.Kind == "":
		return errors.New("kind is missing")
	case e.Severity < 0 || e.Severity > 7:
		return fmt.Errorf("severity %d is outside 0-7", e.Severity)
	case !hex64.MatchString(e.RawSHA256):
		return errors.New("raw_sha256 is not 64 lowercase hex characters")
	}
	return nil
}
