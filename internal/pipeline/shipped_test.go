package pipeline

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/config"
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
	}
}
