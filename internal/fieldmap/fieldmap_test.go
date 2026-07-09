package fieldmap

import (
	"crypto/sha256"
	"encoding/hex"
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
	wantDigest := sha256.Sum256(raw)
	if e.RawSHA256 != hex.EncodeToString(wantDigest[:]) {
		t.Errorf("raw digest not SHA-256 of raw: got %q", e.RawSHA256)
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

func TestApplyParsesAnEpochTimestampWithFractionalSeconds(t *testing.T) {
	m := load(t)
	m.TSLayout = "epoch"
	e, err := m.Apply(map[string]string{"timestamp": "1700000000.25"}, []byte("x"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if e.TS.Unix() != 1700000000 || e.TS.Nanosecond() != 250000000 {
		t.Errorf("epoch timestamp wrong: unix=%d nanosecond=%d", e.TS.Unix(), e.TS.Nanosecond())
	}
}

func TestApplyParsesATimestampInAnExplicitGoLayout(t *testing.T) {
	m := load(t)
	m.TSLayout = "2006-01-02 15:04:05"
	e, err := m.Apply(map[string]string{"timestamp": "2026-09-15 04:05:06"}, []byte("x"))
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if e.TS.Format("2006-01-02T15:04:05Z") != "2026-09-15T04:05:06Z" {
		t.Errorf("custom-layout timestamp wrong: %v", e.TS)
	}
}

func TestSeverityNumericAndUnknownTiers(t *testing.T) {
	m := load(t)
	if got := m.severity("3"); got != 3 {
		t.Errorf("numeric-string tier: got %d, want 3", got)
	}
	if got := m.severity("not-a-level"); got != 5 {
		t.Errorf("unknown-value tier: got %d, want default 5", got)
	}
}

func TestLoadFailsOnAMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join("testdata", "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestLoadRejectsAMapWithoutFieldsOrFormat(t *testing.T) {
	if _, err := Load(filepath.Join("testdata", "incomplete.yaml")); err == nil {
		t.Error("expected an error for a map missing format and fields")
	}
}
