package sink

// NewKafka is on the roadmap: the broker client is not vendored yet, so it
// refuses rather than silently dropping events.
func NewKafka(brokers []string, topic string) (Sink, error) {
	return nil, ErrNotImplemented
}
