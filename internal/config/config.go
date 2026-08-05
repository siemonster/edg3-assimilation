// Package config reads the assimilation pipeline's YAML configuration.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Input is one file to read and the format it holds.
type Input struct {
	Format string `yaml:"format"`
	Path   string `yaml:"path"`
}

// SinkConfig selects the destination.
type SinkConfig struct {
	Type    string   `yaml:"type"`
	Path    string   `yaml:"path"`
	Brokers []string `yaml:"brokers"`
	Topic   string   `yaml:"topic"`
}

// RegistryConfig points at the control API that serves field maps.
type RegistryConfig struct {
	Endpoint string `yaml:"endpoint"`
	Poll     string `yaml:"poll"`
}

// Config is the whole file.
type Config struct {
	SchemaMaps string         `yaml:"schema_maps"`
	Inputs     []Input        `yaml:"inputs"`
	Sink       SinkConfig     `yaml:"sink"`
	Registry   RegistryConfig `yaml:"registry"`
}

// Load reads and checks a configuration file.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	if c.SchemaMaps == "" {
		return Config{}, fmt.Errorf("%s: schema_maps is required", path)
	}
	if len(c.Inputs) == 0 {
		return Config{}, fmt.Errorf("%s: at least one input is required", path)
	}
	for i, in := range c.Inputs {
		if in.Format == "" || in.Path == "" {
			return Config{}, fmt.Errorf("%s: input %d needs a format and a path", path, i)
		}
	}
	switch c.Sink.Type {
	case "stdout":
	case "file":
		if c.Sink.Path == "" {
			return Config{}, fmt.Errorf("%s: the file sink needs a path", path)
		}
	case "kafka":
		if len(c.Sink.Brokers) == 0 || c.Sink.Topic == "" {
			return Config{}, fmt.Errorf("%s: the kafka sink needs brokers and a topic", path)
		}
	default:
		return Config{}, fmt.Errorf("%s: unsupported sink type %q", path, c.Sink.Type)
	}
	return c, nil
}
