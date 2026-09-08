package adapters

import "testing"

const eveLine = `{"timestamp":"2026-09-15T04:05:06.123456+0000","event_type":"alert","host":"sensor-1",` +
	`"src_ip":"10.1.1.5","dest_port":443,"alert":{"signature":"ET TROJAN test","severity":2}}`

func TestSuricataFlattensNestedObjectsWithDottedKeys(t *testing.T) {
	rec, err := NewSuricataEVE().Parse([]byte(eveLine))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for key, want := range map[string]string{
		"timestamp": "2026-09-15T04:05:06.123456+0000", "event_type": "alert", "host": "sensor-1",
		"src_ip": "10.1.1.5", "dest_port": "443", "alert.signature": "ET TROJAN test", "alert.severity": "2"} {
		if rec[key] != want {
			t.Errorf("%s = %q, want %q", key, rec[key], want)
		}
	}
}

func TestSuricataRejectsNonObjectsAndBrokenJSON(t *testing.T) {
	for _, line := range []string{"[1,2]", "{not json}", `"a string"`, "{}"} {
		if _, err := NewSuricataEVE().Parse([]byte(line)); err == nil {
			t.Errorf("expected an error for %q", line)
		}
	}
}

func TestSuricataFlattensBooleanFields(t *testing.T) {
	rec, err := NewSuricataEVE().Parse([]byte(`{"timestamp":"2026-09-15T04:05:06Z","tls":{"resumed":true,"established":false}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec["tls.resumed"] != "true" {
		t.Errorf("tls.resumed = %q, want %q", rec["tls.resumed"], "true")
	}
	if rec["tls.established"] != "false" {
		t.Errorf("tls.established = %q, want %q", rec["tls.established"], "false")
	}
}

func TestSuricataReturnsNilForBlankLines(t *testing.T) {
	for _, line := range []string{"", "   ", "\t"} {
		rec, err := NewSuricataEVE().Parse([]byte(line))
		if rec != nil || err != nil {
			t.Errorf("blank line %q must return (nil, nil), got rec=%v err=%v", line, rec, err)
		}
	}
}
