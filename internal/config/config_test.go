package config

import (
	"os"
	"path/filepath"
	"testing"
)

const good = `
schema_maps: schemas/maps
inputs:
  - format: suricata-eve
    path: testdata/suricata-eve.in
sink:
  type: file
  path: /tmp/out.jsonl
registry:
  endpoint: https://assim-api.edg3.io/v1/maps
  poll: 15m
`

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadReadsInputsSinkAndRegistry(t *testing.T) {
	c, err := Load(write(t, good))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.SchemaMaps != "schemas/maps" || len(c.Inputs) != 1 {
		t.Fatalf("unexpected config: %+v", c)
	}
	if c.Inputs[0].Format != "suricata-eve" || c.Sink.Type != "file" || c.Sink.Path != "/tmp/out.jsonl" {
		t.Errorf("fields wrong: %+v", c)
	}
	if c.Registry.Endpoint == "" || c.Registry.Poll != "15m" {
		t.Errorf("registry not read: %+v", c.Registry)
	}
}

func TestLoadRejectsIncompleteConfigs(t *testing.T) {
	cases := map[string]string{
		"no inputs":      "schema_maps: schemas/maps\nsink:\n  type: stdout\n",
		"no sink type":   "schema_maps: m\ninputs:\n  - format: zeek-conn\n    path: x\nsink: {}\n",
		"file no path":   "schema_maps: m\ninputs:\n  - format: zeek-conn\n    path: x\nsink:\n  type: file\n",
		"unknown sink":   "schema_maps: m\ninputs:\n  - format: zeek-conn\n    path: x\nsink:\n  type: carrier-pigeon\n",
		"input no path":  "schema_maps: m\ninputs:\n  - format: zeek-conn\nsink:\n  type: stdout\n",
		"no schema maps": "inputs:\n  - format: zeek-conn\n    path: x\nsink:\n  type: stdout\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

// Additional test cases per Task 7 instructions

func TestLoadRejectsKafkaWithoutBrokersOrTopic(t *testing.T) {
	kafkaNoBrokers := `
schema_maps: schemas/maps
inputs:
  - format: syslog5424
    path: /tmp/input.log
sink:
  type: kafka
registry:
  endpoint: https://assim-api.edg3.io/v1/maps
  poll: 15m
`
	if _, err := Load(write(t, kafkaNoBrokers)); err == nil {
		t.Errorf("kafka without brokers and topic: expected an error")
	}
}

func TestLoadAcceptsKafkaWithBrokersAndTopic(t *testing.T) {
	kafkaGood := `
schema_maps: schemas/maps
inputs:
  - format: suricata-eve
    path: testdata/suricata-eve.in
sink:
  type: kafka
  brokers:
    - kafka-broker-1:9092
    - kafka-broker-2:9092
  topic: assimilation-events
registry:
  endpoint: https://assim-api.edg3.io/v1/maps
  poll: 15m
`
	c, err := Load(write(t, kafkaGood))
	if err != nil {
		t.Fatalf("kafka with brokers and topic: %v", err)
	}
	if c.Sink.Type != "kafka" {
		t.Errorf("sink type: expected kafka, got %q", c.Sink.Type)
	}
	if len(c.Sink.Brokers) != 2 {
		t.Errorf("brokers count: expected 2, got %d", len(c.Sink.Brokers))
	}
	if c.Sink.Brokers[0] != "kafka-broker-1:9092" || c.Sink.Brokers[1] != "kafka-broker-2:9092" {
		t.Errorf("brokers: %v", c.Sink.Brokers)
	}
	if c.Sink.Topic != "assimilation-events" {
		t.Errorf("topic: expected assimilation-events, got %q", c.Sink.Topic)
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Errorf("missing file: expected an error")
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	malformed := "inputs: [unclosed"
	_, err := Load(write(t, malformed))
	if err == nil {
		t.Errorf("malformed yaml: expected an error")
	}
}

func TestLoadAcceptsStdoutSink(t *testing.T) {
	stdoutGood := `
schema_maps: schemas/maps
inputs:
  - format: syslog5424
    path: /tmp/input.log
sink:
  type: stdout
registry:
  endpoint: https://assim-api.edg3.io/v1/maps
  poll: 15m
`
	c, err := Load(write(t, stdoutGood))
	if err != nil {
		t.Fatalf("stdout sink: %v", err)
	}
	if c.Sink.Type != "stdout" {
		t.Errorf("sink type: expected stdout, got %q", c.Sink.Type)
	}
}
