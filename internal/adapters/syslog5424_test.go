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
	for _, line := range []string{"not syslog at all", "<999>1 2026-09-15T04:05:06Z h a p - - m", "<134>2 2026-09-15T04:05:06Z h a p - - m"} {
		if _, err := NewSyslog5424().Parse([]byte(line)); err == nil {
			t.Errorf("expected an error for %q", line)
		}
	}
}

func TestSyslogReturnsNilForBlankLines(t *testing.T) {
	for _, line := range []string{"", "   ", "\t"} {
		rec, err := NewSyslog5424().Parse([]byte(line))
		if rec != nil || err != nil {
			t.Errorf("blank line %q must return (nil, nil), got rec=%v err=%v", line, rec, err)
		}
	}
}

func TestSyslogDropsNILVALUEFields(t *testing.T) {
	rec, err := NewSyslog5424().Parse([]byte("<134>1 2026-09-15T04:05:06Z fw-edge-1 suricata - - - signature fired"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, key := range []string{"procid", "msgid"} {
		if v, ok := rec[key]; ok {
			t.Errorf("%s must be dropped for RFC 5424 NILVALUE, got %q", key, v)
		}
	}
	if rec["app"] != "suricata" {
		t.Errorf("app = %q, want suricata", rec["app"])
	}
}

func TestForReturnsAnErrorForAnUnknownFormat(t *testing.T) {
	if _, err := For("splunk-magic"); err == nil {
		t.Error("unknown formats must be refused")
	}
}

func TestForReturnsAWorkingSyslog5424Adapter(t *testing.T) {
	a, err := For("syslog5424")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if _, err := a.Parse([]byte(sample)); err != nil {
		t.Errorf("adapter from For must parse a real line: %v", err)
	}
}
