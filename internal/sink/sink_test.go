package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/schema"
)

func events() []schema.Event {
	return []schema.Event{{Schema: schema.CanonicalURN, TS: time.Unix(1757000000, 0).UTC(),
		Source: "zeek-conn", Kind: "network.flow", Severity: 5, RawSHA256: strings.Repeat("b", 64)}}
}

func TestStdoutWritesOneJSONLinePerEvent(t *testing.T) {
	var buf bytes.Buffer
	s := NewStdout(&buf)
	if err := s.Write(context.Background(), events()); err != nil {
		t.Fatalf("write: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want 1 line, got %d", len(lines))
	}
	var back schema.Event
	if err := json.Unmarshal([]byte(lines[0]), &back); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	want := events()[0]
	if back.Schema != want.Schema || back.Source != want.Source || !back.TS.Equal(want.TS) ||
		back.Kind != want.Kind || back.Severity != want.Severity || back.RawSHA256 != want.RawSHA256 {
		t.Errorf("round trip lost fields: got %+v, want %+v", back, want)
	}
}

func TestFileAppendsAcrossWritesAndSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	for i := 0; i < 2; i++ {
		s, err := NewFile(path)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := s.Write(context.Background(), events()); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := strings.Count(strings.TrimSpace(string(raw)), "\n") + 1; got != 2 {
		t.Errorf("want 2 appended lines, got %d", got)
	}
}

func TestFileCreatedWithMode0o600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.jsonl")
	s, err := NewFile(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Write(context.Background(), events()); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := stat.Mode().Perm(); perm != 0o600 {
		t.Errorf("want file mode 0o600, got 0o%o", perm)
	}
}

func TestKafkaIsDeclaredButNotImplemented(t *testing.T) {
	_, err := NewKafka([]string{"localhost:9092"}, "events")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("want ErrNotImplemented, got %v", err)
	}
}

func TestWriteRejectsAnInvalidEvent(t *testing.T) {
	bad := events()
	bad[0].Severity = 9
	if err := NewStdout(&bytes.Buffer{}).Write(context.Background(), bad); err == nil {
		t.Error("sinks must not emit events that fail validation")
	}
}

func TestWriterSinkRejectsAnAlreadyCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var buf bytes.Buffer
	s := NewStdout(&buf)
	if err := s.Write(ctx, events()); err == nil {
		t.Error("Write must return an error for a cancelled context")
	}
	if buf.Len() != 0 {
		t.Error("Write must not write anything when context is already cancelled")
	}
}

func TestBatchAtomicity(t *testing.T) {
	batch := events()
	batch = append(batch, schema.Event{
		Schema:    schema.CanonicalURN,
		TS:        time.Unix(1757000000, 0).UTC(),
		Source:    "zeek-conn",
		Kind:      "network.flow",
		Severity:  9, // invalid: outside 0-7
		RawSHA256: strings.Repeat("b", 64),
	})
	var buf bytes.Buffer
	s := NewStdout(&buf)
	if err := s.Write(context.Background(), batch); err == nil {
		t.Error("Write must return error when a later event is invalid")
	}
	if buf.Len() != 0 {
		t.Errorf("batch with invalid later event must write nothing, but wrote %d bytes", buf.Len())
	}
}
