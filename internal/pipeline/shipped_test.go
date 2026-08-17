package pipeline

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/config"
	"github.com/siemonster/edg3-assimilation/internal/schema"
	"github.com/siemonster/edg3-assimilation/internal/sink"
)

func TestEveryShippedMapNormalisesItsSampleFile(t *testing.T) {
	for _, format := range []string{"syslog5424", "suricata-eve", "zeek-conn"} {
		c := config.Config{SchemaMaps: "../../schemas/maps",
			Inputs: []config.Input{{Format: format, Path: "../../testdata/" + format + ".in"}},
			Sink:   config.SinkConfig{Type: "stdout"}}
		var buf bytes.Buffer
		stats, err := Run(context.Background(), c, sink.NewStdout(&buf), time.Time{})
		if err != nil {
			t.Errorf("%s: %v", format, err)
			continue
		}
		if stats.Emitted != 2 || stats.Failed != 0 {
			t.Errorf("%s: stats = %+v, want 2 emitted and 0 failed", format, stats)
		}

		// For suricata-eve, verify the severity lookup table is applied:
		// sample severity 2 → canonical 4, sample severity 3 → canonical 6.
		if format == "suricata-eve" {
			decoder := json.NewDecoder(bytes.NewReader(buf.Bytes()))
			wantSeverities := []int{4, 6}
			for i, wantSev := range wantSeverities {
				var e schema.Event
				if err := decoder.Decode(&e); err != nil {
					t.Errorf("%s event %d: decode failed: %v", format, i, err)
					break
				}
				if e.Severity != wantSev {
					t.Errorf("%s event %d: severity = %d, want %d", format, i, e.Severity, wantSev)
				}
			}
		}
	}
}
