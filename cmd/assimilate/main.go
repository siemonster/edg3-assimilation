// Command assimilate normalises security telemetry into one canonical shape.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/siemonster/edg3-assimilation/internal/config"
	"github.com/siemonster/edg3-assimilation/internal/pipeline"
	"github.com/siemonster/edg3-assimilation/internal/sink"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to the pipeline configuration")
	dryRun := flag.Bool("dry-run", false, "parse and validate without writing to the sink")
	sinceFlag := flag.String("since", "", "drop events older than this RFC 3339 timestamp")
	flag.Parse()

	if err := run(*configPath, *dryRun, *sinceFlag); err != nil {
		fmt.Fprintln(os.Stderr, "assimilate:", err)
		os.Exit(1)
	}
}

func run(configPath string, dryRun bool, sinceFlag string) error {
	c, err := config.Load(configPath)
	if err != nil {
		return err
	}
	var since time.Time
	if sinceFlag != "" {
		if since, err = time.Parse(time.RFC3339, sinceFlag); err != nil {
			return fmt.Errorf("--since: %w", err)
		}
	}
	out, err := open(c, dryRun)
	if err != nil {
		return err
	}
	defer out.Close()
	stats, err := pipeline.Run(context.Background(), c, out, since)
	fmt.Fprintf(os.Stderr, "read=%d emitted=%d skipped=%d failed=%d\n",
		stats.Read, stats.Emitted, stats.Skipped, stats.Failed)
	return err
}

func open(c config.Config, dryRun bool) (sink.Sink, error) {
	if dryRun {
		return sink.NewStdout(io.Discard), nil
	}
	switch c.Sink.Type {
	case "stdout":
		return sink.NewStdout(os.Stdout), nil
	case "file":
		return sink.NewFile(c.Sink.Path)
	case "kafka":
		return sink.NewKafka(c.Sink.Brokers, c.Sink.Topic)
	default:
		return nil, fmt.Errorf("unsupported sink type %q", c.Sink.Type)
	}
}
