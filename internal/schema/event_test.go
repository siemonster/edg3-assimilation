package schema

import (
	"strings"
	"testing"
	"time"
)

func valid() Event {
	return Event{Schema: CanonicalURN, TS: time.Unix(1757000000, 0).UTC(), Source: "suricata-eve",
		Kind: "alert", Severity: 3, RawSHA256: strings.Repeat("a", 64)}
}

func TestValidateAcceptsACompleteEvent(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
}

func TestValidateRejectsEachMissingOrOutOfRangeField(t *testing.T) {
	cases := map[string]func(*Event){
		"foreign schema": func(e *Event) { e.Schema = "urn:other" },
		"zero timestamp": func(e *Event) { e.TS = time.Time{} },
		"no source":      func(e *Event) { e.Source = "" },
		"no kind":        func(e *Event) { e.Kind = "" },
		"severity high":  func(e *Event) { e.Severity = 8 },
		"severity low":   func(e *Event) { e.Severity = -1 },
		"short digest":   func(e *Event) { e.RawSHA256 = "abc" },
		"nonhex digest":  func(e *Event) { e.RawSHA256 = strings.Repeat("z", 64) },
	}
	for name, break_ := range cases {
		e := valid()
		break_(&e)
		if err := e.Validate(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestValidateAcceptsTheSeverityBoundaries(t *testing.T) {
	for _, sev := range []int{0, 7} {
		e := valid()
		e.Severity = sev
		if err := e.Validate(); err != nil {
			t.Errorf("severity %d should be accepted: %v", sev, err)
		}
	}
}

func TestCanonicalURNIsPinned(t *testing.T) {
	if CanonicalURN != "urn:edg3:assim:canon:v1:7f3c9ab2" {
		t.Fatalf("the canonical URN changed: %q", CanonicalURN)
	}
}
