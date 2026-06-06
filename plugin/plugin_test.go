package plugin

import (
	"testing"

	"github.com/kanywst/opa-authzen-plugin/internal"
)

func TestPluginName(t *testing.T) {
	// Verify the plugin name is correct
	if PluginName != "authzen" {
		t.Errorf("PluginName should be 'authzen', got %q", PluginName)
	}

	if PluginName != internal.PluginName {
		t.Errorf("PluginName mismatch with internal: got %q, want %q", PluginName, internal.PluginName)
	}
}

func TestFactoryExists(t *testing.T) {
	// Verify Factory type exists and is exported
	factory := Factory{}
	if factory == (Factory{}) {
		t.Log("Factory is a valid empty struct (as expected)")
	}
}

func TestValidateValidConfig(t *testing.T) {
	factory := Factory{}
	config := []byte(`{"path": "authzen", "decision": "allow"}`)

	result, err := factory.Validate(nil, config)
	if err != nil {
		t.Fatalf("Validate should not error for valid config: %v", err)
	}

	cfg, ok := result.(*internal.Config)
	if !ok {
		t.Fatalf("Validate should return *internal.Config, got %T", result)
	}

	if cfg.Path != "authzen" {
		t.Errorf("Path mismatch: got %q, want %q", cfg.Path, "authzen")
	}
	if cfg.Decision != "allow" {
		t.Errorf("Decision mismatch: got %q, want %q", cfg.Decision, "allow")
	}
}

func TestValidateDefaults(t *testing.T) {
	factory := Factory{}
	config := []byte(`{}`)

	result, err := factory.Validate(nil, config)
	if err != nil {
		t.Fatalf("Validate should handle empty config: %v", err)
	}

	cfg, ok := result.(*internal.Config)
	if !ok {
		t.Fatalf("Validate should return *internal.Config, got %T", result)
	}

	if cfg.Path != "authzen" {
		t.Errorf("Path should default to 'authzen', got %q", cfg.Path)
	}
	if cfg.Decision != "allow" {
		t.Errorf("Decision should default to 'allow', got %q", cfg.Decision)
	}
}

func TestValidateCapabilities(t *testing.T) {
	factory := Factory{}

	t.Run("valid URNs are parsed, trimmed, and scheme-canonicalized", func(t *testing.T) {
		// RFC 8141 §2: the "urn:" scheme is case-insensitive, so "URN:" is
		// accepted and the prefix is canonicalized to lowercase.
		config := []byte(`{"capabilities": ["urn:openid:authzen:capability:access-request", "  URN:example:cap  "]}`)
		result, err := factory.Validate(nil, config)
		if err != nil {
			t.Fatalf("Validate should accept URN capabilities: %v", err)
		}
		cfg := result.(*internal.Config)
		want := []string{"urn:openid:authzen:capability:access-request", "urn:example:cap"}
		if len(cfg.Capabilities) != len(want) {
			t.Fatalf("got %d capabilities, want %d: %v", len(cfg.Capabilities), len(want), cfg.Capabilities)
		}
		for i := range want {
			if cfg.Capabilities[i] != want[i] {
				t.Errorf("capabilities[%d] = %q, want %q", i, cfg.Capabilities[i], want[i])
			}
		}
	})

	t.Run("empty entry is rejected", func(t *testing.T) {
		config := []byte(`{"capabilities": ["urn:example:cap", "   "]}`)
		if _, err := factory.Validate(nil, config); err == nil {
			t.Error("Validate should reject an empty capability entry")
		}
	})

	t.Run("non-URN entry is rejected", func(t *testing.T) {
		config := []byte(`{"capabilities": ["access-request"]}`)
		if _, err := factory.Validate(nil, config); err == nil {
			t.Error("Validate should reject a capability that is not a URN")
		}
	})
}

func TestValidateInvalidJSON(t *testing.T) {
	factory := Factory{}
	config := []byte(`invalid json`)

	_, err := factory.Validate(nil, config)
	if err == nil {
		t.Error("Validate should error for invalid JSON")
	}
}

func TestValidateCustomPaths(t *testing.T) {
	factory := Factory{}

	tests := []struct {
		config string
		path   string
		rule   string
	}{
		{`{"path": "custom/path", "decision": "permit"}`, "custom/path", "permit"},
		{`{"path": "data.authz", "decision": "is_allowed"}`, "data.authz", "is_allowed"},
	}

	for _, tt := range tests {
		result, err := factory.Validate(nil, []byte(tt.config))
		if err != nil {
			t.Errorf("Validate failed for config %q: %v", tt.config, err)
			continue
		}

		cfg := result.(*internal.Config)
		if cfg.Path != tt.path {
			t.Errorf("Path mismatch: got %q, want %q", cfg.Path, tt.path)
		}
		if cfg.Decision != tt.rule {
			t.Errorf("Decision mismatch: got %q, want %q", cfg.Decision, tt.rule)
		}
	}
}
