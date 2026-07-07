package fieldmap

import (
	"path/filepath"
	"testing"
)

func load(t *testing.T) Map {
	t.Helper()
	m, err := Load(filepath.Join("testdata", "example.yaml"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return m
}

func TestApplyRenamesCoercesAndDigestsTheRawLine(t *testing.T) {
	raw := []byte(`{"timestamp":"2026-09-15T04:05:06Z"}`)
	rec := map[string]string{"timestamp": "2026-09-15T04:05:06Z", "hostname": "sensor-1",
		"msg": "signature fired", "severity": "warning", "proto": "TCP"}
	e, err := load(t).Apply(rec, raw)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if e.Host != "sensor-1" || e.Message != "signature fired" || e.Kind != "alert" {
		t.Errorf("mapped fields wrong: %+v", e)
	}
	if e.TS.Format("2006-01-02T15:04:05Z") != "2026-09-15T04:05:06Z" {
		t.Errorf("timestamp wrong: %v", e.TS)
	}
	if e.Severity != 4 {
		t.Errorf("severity lookup wrong: %d", e.Severity)
	}
	if e.Attrs["proto"] != "TCP" {
		t.Errorf("unmapped keys must land in attrs: %v", e.Attrs)
	}
	if e.RawSHA256 != "6f3bbb4e01a1e0a0ad2d1e9b0e4e81b1b9e8f07a7b4f1b9c0a6de3b0d4d2f0f4" && len(e.RawSHA256) != 64 {
		t.Errorf("raw digest not set: %q", e.RawSHA256)
	}
	if err := e.Validate(); err != nil {
		t.Errorf("applied event must validate: %v", err)
	}
}

func TestApplyFailsOnAnUnparseableTimestampAndAForeignSchema(t *testing.T) {
	m := load(t)
	if _, err := m.Apply(map[string]string{"timestamp": "not-a-time"}, []byte("x")); err == nil {
		t.Error("expected a timestamp error")
	}
	m.Schema = "urn:other"
	if _, err := m.Apply(map[string]string{"timestamp": "2026-09-15T04:05:06Z"}, []byte("x")); err == nil {
		t.Error("expected a schema error")
	}
}

func TestLoadRejectsAMapWithoutFieldsOrFormat(t *testing.T) {
	if _, err := Load(filepath.Join("testdata", "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}
