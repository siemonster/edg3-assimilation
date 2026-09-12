package adapters

import "testing"

func TestZeekUsesTheFieldsHeaderAndSkipsDirectives(t *testing.T) {
	a := NewZeekConn()
	for _, directive := range []string{"#separator \\x09", "#fields\tts\tid.orig_h\tproto\tduration"} {
		rec, err := a.Parse([]byte(directive))
		if err != nil || rec != nil {
			t.Fatalf("directive %q must be consumed silently: rec=%v err=%v", directive, rec, err)
		}
	}
	rec, err := a.Parse([]byte("1757000000.123456\t10.1.1.5\ttcp\t0.25"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for key, want := range map[string]string{"ts": "1757000000.123456", "id.orig_h": "10.1.1.5",
		"proto": "tcp", "duration": "0.25"} {
		if rec[key] != want {
			t.Errorf("%s = %q, want %q", key, rec[key], want)
		}
	}
}

func TestZeekRefusesDataBeforeAHeaderAndOnColumnMismatch(t *testing.T) {
	if _, err := NewZeekConn().Parse([]byte("1757000000\t10.1.1.5")); err == nil {
		t.Error("data before #fields must be refused")
	}
	a := NewZeekConn()
	if _, err := a.Parse([]byte("#fields\tts\tproto")); err != nil {
		t.Fatalf("header: %v", err)
	}
	if _, err := a.Parse([]byte("1757000000\ttcp\textra")); err == nil {
		t.Error("column count mismatch must be refused")
	}
}

func TestZeekSkipsDashAndEmptyMarkers(t *testing.T) {
	a := NewZeekConn()
	if _, err := a.Parse([]byte("#fields\tts\tid.orig_h\tproto\tduration")); err != nil {
		t.Fatalf("header: %v", err)
	}
	rec, err := a.Parse([]byte("1757000000.123456\t-\ttcp\t(empty)"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Assert that "-" and "(empty)" values are not present
	if _, ok := rec["id.orig_h"]; ok {
		t.Error("dash marker should be skipped, but id.orig_h is present")
	}
	if _, ok := rec["duration"]; ok {
		t.Error("(empty) marker should be skipped, but duration is present")
	}
	// Assert that real values are present
	if rec["ts"] != "1757000000.123456" {
		t.Errorf("ts = %q, want %q", rec["ts"], "1757000000.123456")
	}
	if rec["proto"] != "tcp" {
		t.Errorf("proto = %q, want %q", rec["proto"], "tcp")
	}
}

func TestZeekReturnsNilForBlankLines(t *testing.T) {
	a := NewZeekConn()
	if _, err := a.Parse([]byte("#fields\tts\tproto")); err != nil {
		t.Fatalf("header: %v", err)
	}
	cases := []string{"", "   ", "\t"}
	for _, line := range cases {
		rec, err := a.Parse([]byte(line))
		if rec != nil {
			t.Errorf("line %q should return nil record, got %v", line, rec)
		}
		if err != nil {
			t.Errorf("line %q should return nil error, got %v", line, err)
		}
	}
}
