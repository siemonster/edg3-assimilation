package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/config"
	"github.com/siemonster/edg3-assimilation/internal/schema"
	"github.com/siemonster/edg3-assimilation/internal/sink"
)

func conf() config.Config {
	return config.Config{SchemaMaps: "testdata",
		Inputs: []config.Input{{Format: "zeek-conn", Path: filepath.Join("testdata", "zeek-conn.in")}},
		Sink:   config.SinkConfig{Type: "stdout"}}
}

func TestRunNormalisesEveryDataLineAndSkipsDirectives(t *testing.T) {
	var buf bytes.Buffer
	stats, err := Run(context.Background(), conf(), sink.NewStdout(&buf), time.Time{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Emitted != 2 || stats.Failed != 1 {
		t.Fatalf("stats = %+v, want 2 emitted and 1 failed", stats)
	}
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	for i, wantHost := range []string{"10.1.1.5", "10.1.1.6"} {
		var e schema.Event
		if err := decoder.Decode(&e); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if e.Host != wantHost || e.Kind != "network.flow" || e.Schema != schema.CanonicalURN {
			t.Errorf("event %d wrong: %+v", i, e)
		}
	}
}

func TestRunHonoursSinceAndReportsAMissingMap(t *testing.T) {
	var buf bytes.Buffer
	stats, err := Run(context.Background(), conf(), sink.NewStdout(&buf), time.Unix(1757000050, 0))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Emitted != 1 || stats.Skipped != 1 {
		t.Errorf("since filter wrong: %+v", stats)
	}
	broken := conf()
	broken.SchemaMaps = filepath.Join("testdata", "absent")
	if _, err := Run(context.Background(), broken, sink.NewStdout(&buf), time.Time{}); err == nil {
		t.Error("a missing field map must fail the run")
	}
}

func TestRunFlushesThePendingBatchBeforeAScannerError(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "zeek-conn.in")
	body := "#fields\tts\tid.orig_h\tproto\tduration\n" +
		"1757000000.000000\t10.1.1.5\ttcp\t0.25\n" +
		"1757000100.000000\t10.1.1.6\tudp\t1.50\n" +
		strings.Repeat("x", 2*1024*1024) + "\n"
	if err := os.WriteFile(in, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	c := config.Config{SchemaMaps: "testdata",
		Inputs: []config.Input{{Format: "zeek-conn", Path: in}},
		Sink:   config.SinkConfig{Type: "stdout"}}

	var buf bytes.Buffer
	stats, err := Run(context.Background(), c, sink.NewStdout(&buf), time.Time{})
	if err == nil {
		t.Fatal("expected a scanner error for the oversized line")
	}
	if stats.Emitted != 2 {
		t.Errorf("events parsed before the scanner error must still be flushed: stats=%+v", stats)
	}
}
