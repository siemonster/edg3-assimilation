package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
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
