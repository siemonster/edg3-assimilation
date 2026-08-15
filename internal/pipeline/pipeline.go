// Package pipeline reads each configured input and writes canonical events.
package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/adapters"
	"github.com/siemonster/edg3-assimilation/internal/config"
	"github.com/siemonster/edg3-assimilation/internal/fieldmap"
	"github.com/siemonster/edg3-assimilation/internal/schema"
	"github.com/siemonster/edg3-assimilation/internal/sink"
)

const batchSize = 500

// Stats counts one run.
type Stats struct {
	Read    int
	Emitted int
	Skipped int
	Failed  int
}

// Run normalises every configured input into out, dropping events older than
// since when since is non-zero.
func Run(ctx context.Context, c config.Config, out sink.Sink, since time.Time) (Stats, error) {
	var stats Stats
	for _, in := range c.Inputs {
		adapter, err := adapters.For(in.Format)
		if err != nil {
			return stats, err
		}
		m, err := fieldmap.Load(filepath.Join(c.SchemaMaps, in.Format+".yaml"))
		if err != nil {
			return stats, err
		}
		f, err := os.Open(in.Path)
		if err != nil {
			return stats, err
		}
		batch := make([]schema.Event, 0, batchSize)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for scanner.Scan() {
			if err := ctx.Err(); err != nil {
				f.Close()
				return stats, err
			}
			line := append([]byte(nil), scanner.Bytes()...)
			stats.Read++
			rec, err := adapter.Parse(line)
			if err != nil {
				stats.Failed++
				continue
			}
			if rec == nil {
				continue // a directive or a blank line
			}
			e, err := m.Apply(rec, line)
			if err != nil || e.Validate() != nil {
				stats.Failed++
				continue
			}
			if !since.IsZero() && e.TS.Before(since) {
				stats.Skipped++
				continue
			}
			batch = append(batch, e)
			if len(batch) == batchSize {
				if err := out.Write(ctx, batch); err != nil {
					f.Close()
					return stats, err
				}
				stats.Emitted += len(batch)
				batch = batch[:0]
			}
		}
		if err := scanner.Err(); err != nil {
			f.Close()
			return stats, fmt.Errorf("%s: %w", in.Path, err)
		}
		if len(batch) > 0 {
			if err := out.Write(ctx, batch); err != nil {
				f.Close()
				return stats, err
			}
			stats.Emitted += len(batch)
		}
		f.Close()
	}
	return stats, nil
}
