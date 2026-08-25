package api

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestOpenAPIParsesAndPinsTheDocumentedSurface(t *testing.T) {
	raw, err := os.ReadFile("openapi.yaml")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var doc struct {
		Servers    []struct{ URL string } `yaml:"servers"`
		Paths      map[string]any         `yaml:"paths"`
		Security   []map[string]any       `yaml:"security"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type   string `yaml:"type"`
				Scheme string `yaml:"scheme"`
			} `yaml:"securitySchemes"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("openapi.yaml is not valid YAML: %v", err)
	}
	if len(doc.Servers) != 1 || !strings.HasPrefix(doc.Servers[0].URL, "https://") {
		t.Errorf("exactly one HTTPS server is expected: %+v", doc.Servers)
	}
	// Pin the server URL exactly to assim-api.edg3.io
	if len(doc.Servers) == 1 && doc.Servers[0].URL != "https://assim-api.edg3.io" {
		t.Errorf("server URL must be exactly https://assim-api.edg3.io, got %s", doc.Servers[0].URL)
	}
	for _, want := range []string{"/v1/pipelines", "/v1/pipelines/{id}/status", "/v1/maps"} {
		if _, ok := doc.Paths[want]; !ok {
			t.Errorf("missing path %s", want)
		}
	}
	if strings.Contains(string(raw), "localhost") || strings.Contains(string(raw), "127.0.0.1") {
		t.Error("the spec must not reference loopback hosts")
	}

	// Pin the top-level security to require bearerAuth
	if len(doc.Security) == 0 {
		t.Error("top-level security is missing")
	}
	bearerAuthFound := false
	for _, sec := range doc.Security {
		if _, ok := sec["bearerAuth"]; ok {
			bearerAuthFound = true
			break
		}
	}
	if !bearerAuthFound {
		t.Error("top-level security must require bearerAuth")
	}

	// Pin the bearerAuth scheme to type: http and scheme: bearer
	bearerScheme, ok := doc.Components.SecuritySchemes["bearerAuth"]
	if !ok {
		t.Error("components.securitySchemes.bearerAuth is missing")
	} else {
		if bearerScheme.Type != "http" {
			t.Errorf("bearerAuth type must be 'http', got %s", bearerScheme.Type)
		}
		if bearerScheme.Scheme != "bearer" {
			t.Errorf("bearerAuth scheme must be 'bearer', got %s", bearerScheme.Scheme)
		}
	}
}
