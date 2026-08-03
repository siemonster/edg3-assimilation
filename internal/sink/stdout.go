package sink

import (
	"context"
	"encoding/json"
	"io"

	"github.com/siemonster/edg3-assimilation/internal/schema"
)

type writerSink struct {
	encoder *json.Encoder
	closer  io.Closer
}

// NewStdout writes one JSON object per event to w.
func NewStdout(w io.Writer) Sink { return &writerSink{encoder: json.NewEncoder(w)} }

func (s *writerSink) Write(ctx context.Context, events []schema.Event) error {
	if err := validate(events); err != nil {
		return err
	}
	for _, e := range events {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.encoder.Encode(e); err != nil {
			return err
		}
	}
	return nil
}

func (s *writerSink) Close() error {
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}
