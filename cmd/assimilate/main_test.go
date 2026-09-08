package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/siemonster/edg3-assimilation/internal/config"
	"github.com/siemonster/edg3-assimilation/internal/schema"
)

func TestOpenSelectsTheConfiguredSink(t *testing.T) {
	cases := []struct {
		name    string
		sink    config.SinkConfig
		dryRun  bool
		wantErr bool
	}{
		{name: "dry run always uses stdout, even with a bad sink type", sink: config.SinkConfig{Type: "carrier-pigeon"}, dryRun: true},
		{name: "stdout", sink: config.SinkConfig{Type: "stdout"}},
		{name: "file", sink: config.SinkConfig{Type: "file", Path: filepath.Join(t.TempDir(), "out.jsonl")}},
		{name: "kafka is declared but not implemented", sink: config.SinkConfig{Type: "kafka", Brokers: []string{"b:9092"}, Topic: "t"}, wantErr: true},
		{name: "unsupported sink type", sink: config.SinkConfig{Type: "carrier-pigeon"}, wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := open(config.Config{Sink: c.sink}, c.dryRun)
			if c.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			if err := s.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
		})
	}
}

func TestRunProcessesTheShippedExampleDataToStdout(t *testing.T) {
	cfg := `
schema_maps: ../../schemas/maps
inputs:
  - format: suricata-eve
    path: ../../testdata/suricata-eve.in
  - format: zeek-conn
    path: ../../testdata/zeek-conn.in
  - format: syslog5424
    path: ../../testdata/syslog5424.in
sink:
  type: stdout
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	runErr := run(path, false, "")
	w.Close()
	os.Stdout = origStdout

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		t.Fatalf("read piped stdout: %v", err)
	}
	if runErr != nil {
		t.Fatalf("run: %v", runErr)
	}
	if got := bytes.Count(out.Bytes(), []byte(schema.CanonicalURN)); got != 6 {
		t.Errorf("want 6 canonical events on stdout (2 per shipped sample), got %d in: %s", got, out.String())
	}
}
