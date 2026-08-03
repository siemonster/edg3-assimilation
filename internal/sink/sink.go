// Package sink writes canonical events to a destination.
package sink

import (
	"context"
	"errors"
	"fmt"

	"github.com/siemonster/edg3-assimilation/internal/schema"
)

// ErrNotImplemented marks a sink that is declared but not built yet.
var ErrNotImplemented = errors.New("sink is not implemented in this release")

// Sink accepts batches of validated events.
type Sink interface {
	Write(ctx context.Context, events []schema.Event) error
	Close() error
}

func validate(events []schema.Event) error {
	for i, e := range events {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("event %d: %w", i, err)
		}
	}
	return nil
}
