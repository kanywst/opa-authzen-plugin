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

func TestValidateSupportedObligations(t *testing.T) {
	factory := Factory{}

	t.Run("registered types and custom are parsed and trimmed", func(t *testing.T) {
		// The registry is extensible, so an unregistered value is accepted too.
		config := []byte(`{"supported_obligations": ["step-up", "  notification  ", "custom", "urn:example:future"]}`)
		result, err := factory.Validate(nil, config)
		if err != nil {
			t.Fatalf("Validate should accept obligation types: %v", err)
		}
		cfg := result.(*internal.Config)
		want := []string{"step-up", "notification", "custom", "urn:example:future"}
		if len(cfg.SupportedObligations) != len(want) {
			t.Fatalf("got %d obligations, want %d: %v", len(cfg.SupportedObligations), len(want), cfg.SupportedObligations)
		}
		for i := range want {
			if cfg.SupportedObligations[i] != want[i] {
				t.Errorf("supported_obligations[%d] = %q, want %q", i, cfg.SupportedObligations[i], want[i])
			}
		}
	})

	t.Run("empty entry is rejected", func(t *testing.T) {
		config := []byte(`{"supported_obligations": ["step-up", "   "]}`)
		if _, err := factory.Validate(nil, config); err == nil {
			t.Error("Validate should reject an empty obligation entry")
		}
	})

	t.Run("unset leaves the profile disabled", func(t *testing.T) {
		result, err := factory.Validate(nil, []byte(`{}`))
		if err != nil {
			t.Fatalf("Validate should handle a config without obligations: %v", err)
		}
		if got := result.(*internal.Config).SupportedObligations; len(got) != 0 {
			t.Errorf("expected no advertised obligations by default, got %v", got)
		}
	})
}

func TestValidateAccessRequestMetadata(t *testing.T) {
	factory := Factory{}

	t.Run("https URIs are accepted and trimmed", func(t *testing.T) {
		config := []byte(`{"access_request_endpoint": "  https://requests.example.com/access/v1/requests  ", "jwks_uri": "https://pdp.example.com/access/v1/jwks"}`)
		result, err := factory.Validate(nil, config)
		if err != nil {
			t.Fatalf("Validate should accept https URIs: %v", err)
		}
		cfg := result.(*internal.Config)
		if got, want := cfg.AccessRequestEndpoint, "https://requests.example.com/access/v1/requests"; got != want {
			t.Errorf("access_request_endpoint = %q, want %q", got, want)
		}
		if got, want := cfg.JWKSURI, "https://pdp.example.com/access/v1/jwks"; got != want {
			t.Errorf("jwks_uri = %q, want %q", got, want)
		}
	})

	t.Run("non-https is rejected", func(t *testing.T) {
		// The profile requires HTTPS for both members.
		for _, config := range []string{
			`{"access_request_endpoint": "http://requests.example.com/requests"}`,
			`{"jwks_uri": "http://pdp.example.com/jwks"}`,
			`{"access_request_endpoint": "ftp://requests.example.com/requests"}`,
		} {
			if _, err := factory.Validate(nil, []byte(config)); err == nil {
				t.Errorf("Validate should reject a non-https URI: %s", config)
			}
		}
	})

	t.Run("https without a host is rejected", func(t *testing.T) {
		// "https://" parses cleanly but advertises nothing a PEP can reach.
		for _, config := range []string{
			`{"access_request_endpoint": "https://"}`,
			`{"jwks_uri": "https:///jwks"}`,
			`{"access_request_endpoint": "/access/v1/requests"}`,
		} {
			if _, err := factory.Validate(nil, []byte(config)); err == nil {
				t.Errorf("Validate should reject a hostless URI: %s", config)
			}
		}
	})

	t.Run("whitespace-only is normalized to unset", func(t *testing.T) {
		config := []byte(`{"access_request_endpoint": "   ", "jwks_uri": "  "}`)
		result, err := factory.Validate(nil, config)
		if err != nil {
			t.Fatalf("Validate should treat a blank value as unset: %v", err)
		}
		cfg := result.(*internal.Config)
		if cfg.AccessRequestEndpoint != "" || cfg.JWKSURI != "" {
			t.Errorf("expected blank values to normalize to unset, got %q and %q", cfg.AccessRequestEndpoint, cfg.JWKSURI)
		}
	})

	t.Run("unset leaves the profile unadvertised", func(t *testing.T) {
		result, err := factory.Validate(nil, []byte(`{}`))
		if err != nil {
			t.Fatalf("Validate should handle a config without the profile: %v", err)
		}
		cfg := result.(*internal.Config)
		if cfg.AccessRequestEndpoint != "" || cfg.JWKSURI != "" {
			t.Errorf("expected the profile to be unadvertised by default, got %q and %q", cfg.AccessRequestEndpoint, cfg.JWKSURI)
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
