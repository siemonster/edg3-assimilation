package adapters

import "testing"

const sample = `<134>1 2026-09-15T04:05:06Z fw-edge-1 suricata 4211 - - signature fired`

func TestSyslogParsesHeaderAndDerivesSeverityFromPriority(t *testing.T) {
	rec, err := NewSyslog5424().Parse([]byte(sample))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for key, want := range map[string]string{"ts": "2026-09-15T04:05:06Z", "host": "fw-edge-1",
		"app": "suricata", "procid": "4211", "msg": "signature fired", "severity": "6", "facility": "16"} {
		if rec[key] != want {
			t.Errorf("%s = %q, want %q", key, rec[key], want)
		}
	}
}

func TestSyslogRejectsMalformedLines(t *testing.T) {
	for _, line := range []string{"", "not syslog at all", "<999>1 x", "<134>2 2026-09-15T04:05:06Z h a p - - m"} {
		if _, err := NewSyslog5424().Parse([]byte(line)); err == nil {
			t.Errorf("expected an error for %q", line)
		}
	}
}

func TestForReturnsAnErrorForAnUnknownFormat(t *testing.T) {
	if _, err := For("splunk-magic"); err == nil {
		t.Error("unknown formats must be refused")
	}
}
