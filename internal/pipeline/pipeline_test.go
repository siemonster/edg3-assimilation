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

func zeekConfig(path string) config.Config {
	return config.Config{SchemaMaps: "testdata",
		Inputs: []config.Input{{Format: "zeek-conn", Path: path}},
		Sink:   config.SinkConfig{Type: "stdout"}}
}

func conf() config.Config {
	return zeekConfig(filepath.Join("testdata", "zeek-conn.in"))
}

// writeZeek writes body as a Zeek input file in a fresh temp dir and returns
// its path, so a test can exercise Run against a fixture of its own shape
// without adding a new file under testdata.
func writeZeek(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zeek-conn.in")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
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
	_, err = Run(context.Background(), broken, sink.NewStdout(&buf), time.Time{})
	if err == nil {
		t.Fatal("a missing field map must fail the run")
	}
	if !strings.Contains(err.Error(), broken.Inputs[0].Path) {
		t.Errorf("error should name the failing input %q: %v", broken.Inputs[0].Path, err)
	}
}

func TestRunFlushesThePendingBatchBeforeAScannerError(t *testing.T) {
	in := writeZeek(t, "#fields\tts\tid.orig_h\tproto\tduration\n"+
		"1757000000.000000\t10.1.1.5\ttcp\t0.25\n"+
		"1757000100.000000\t10.1.1.6\tudp\t1.50\n"+
		strings.Repeat("x", 2*1024*1024)+"\n")

	var buf bytes.Buffer
	stats, err := Run(context.Background(), zeekConfig(in), sink.NewStdout(&buf), time.Time{})
	if err == nil {
		t.Fatal("expected a scanner error for the oversized line")
	}
	if stats.Emitted != 2 {
		t.Errorf("events parsed before the scanner error must still be flushed: stats=%+v", stats)
	}
}

func TestRunEmitsAnEventWhoseTimestampExactlyEqualsSince(t *testing.T) {
	var buf bytes.Buffer
	since := time.Unix(1757000000, 0) // exactly the first event's ts in conf()
	stats, err := Run(context.Background(), conf(), sink.NewStdout(&buf), since)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Skipped != 0 || stats.Emitted != 2 {
		t.Errorf("an event at exactly --since must be emitted, not skipped: %+v", stats)
	}
}

func TestRunCountsALineThatFailsMappingAsFailed(t *testing.T) {
	// The line parses fine (right column count), but its ts is not a valid
	// epoch value, so fieldmap.Apply fails it rather than adapter.Parse.
	in := writeZeek(t, "#fields\tts\tid.orig_h\tproto\tduration\n"+
		"not-a-number\t10.1.1.9\ttcp\t0.1\n")

	var buf bytes.Buffer
	stats, err := Run(context.Background(), zeekConfig(in), sink.NewStdout(&buf), time.Time{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Failed != 1 || stats.Emitted != 0 {
		t.Fatalf("stats = %+v, want 1 failed and 0 emitted", stats)
	}
}

func TestRunFlushesTheBatchWhenItFillsAndAgainAtEndOfInput(t *testing.T) {
	orig := batchSize
	batchSize = 2
	defer func() { batchSize = orig }()

	in := writeZeek(t, "#fields\tts\tid.orig_h\tproto\tduration\n"+
		"1757000000.000000\t10.1.1.5\ttcp\t0.25\n"+
		"1757000100.000000\t10.1.1.6\tudp\t1.50\n"+
		"1757000200.000000\t10.1.1.7\ttcp\t0.75\n")

	var buf bytes.Buffer
	stats, err := Run(context.Background(), zeekConfig(in), sink.NewStdout(&buf), time.Time{})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Emitted != 3 || stats.Failed != 0 {
		t.Fatalf("stats = %+v, want 3 emitted and 0 failed", stats)
	}
	decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
	hosts := map[string]bool{}
	for i := 0; i < 3; i++ {
		var e schema.Event
		if err := decoder.Decode(&e); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		hosts[e.Host] = true
	}
	if len(hosts) != 3 {
		t.Errorf("want each of 3 events emitted exactly once, got hosts %v", hosts)
	}
}
