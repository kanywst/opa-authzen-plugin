package plugin

import (
	"encoding/base64"
	"encoding/json"
	"strings"
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

// testJWT builds a compact JWS from the given header and claims. The
// signature segment is opaque bytes: Validate cannot verify it, only check
// that one is present.
func testJWT(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	seg := func(v map[string]any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return seg(header) + "." + seg(claims) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
}

func signedMetadataConfig(t *testing.T, extra string, jwt string) []byte {
	t.Helper()
	b, err := json.Marshal(jwt)
	if err != nil {
		t.Fatal(err)
	}
	if extra != "" {
		extra += ", "
	}
	return []byte(`{` + extra + `"signed_metadata": ` + string(b) + `}`)
}

func TestValidateSignedMetadata(t *testing.T) {
	factory := Factory{}
	hs256 := map[string]any{"alg": "HS256", "typ": "JWT"}

	t.Run("a signed JWT with iss is accepted and trimmed", func(t *testing.T) {
		jwt := testJWT(t, hs256, map[string]any{"iss": "https://pdp.example.com"})
		result, err := factory.Validate(nil, signedMetadataConfig(t, "", "  "+jwt+"  "))
		if err != nil {
			t.Fatalf("Validate should accept a well-formed signed_metadata: %v", err)
		}
		if got := result.(*internal.Config).SignedMetadata; got != jwt {
			t.Errorf("signed_metadata = %q, want %q", got, jwt)
		}
	})

	t.Run("claims that agree with the config are accepted", func(t *testing.T) {
		jwt := testJWT(t, hs256, map[string]any{
			"iss":                     "https://pdp.example.com",
			"capabilities":            []string{"Urn:b", "urn:a"},
			"supported_obligations":   []string{"step-up"},
			"access_request_endpoint": "https://requests.example.com/requests",
			"jwks_uri":                "https://pdp.example.com/jwks",
			"search_subject_endpoint": "https://pdp.example.com/access/v1/search/subject",
		})
		extra := `"capabilities": ["urn:a", "URN:b"], "supported_obligations": ["step-up"], "access_request_endpoint": "https://requests.example.com/requests", "jwks_uri": "https://pdp.example.com/jwks", "search": {"subject": "subjects"}`
		if _, err := factory.Validate(nil, signedMetadataConfig(t, extra, jwt)); err != nil {
			t.Fatalf("Validate should accept claims matching the config: %v", err)
		}
	})

	t.Run("malformed values are rejected", func(t *testing.T) {
		claims := map[string]any{"iss": "https://pdp.example.com"}
		valid := testJWT(t, hs256, claims)
		parts := strings.Split(valid, ".")
		for name, tc := range map[string]struct {
			jwt     string
			wantErr string
		}{
			"two parts":            {parts[0] + "." + parts[1], "three dot-separated parts"},
			"JWE (five parts)":     {valid + ".x.y", "three dot-separated parts"},
			"empty signature":      {parts[0] + "." + parts[1] + ".", "no signature"},
			"signature not b64url": {parts[0] + "." + parts[1] + ".a", "signature"},
			"embedded newline":     {parts[0] + "\n." + parts[1] + "." + parts[2], "base64url characters"},
			"padded segment":       {parts[0] + "=." + parts[1] + "." + parts[2], "base64url characters"},
			"header not b64url":    {"a." + parts[1] + "." + parts[2], "header"},
			"claims not JSON":      {parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte("nope")) + "." + parts[2], "claims"},
			"alg none":             {testJWT(t, map[string]any{"alg": "none"}, claims), "alg"},
			"alg missing":          {testJWT(t, map[string]any{"typ": "JWT"}, claims), "alg"},
			"iss missing":          {testJWT(t, hs256, map[string]any{"sub": "x"}), "iss"},
			"iss empty":            {testJWT(t, hs256, map[string]any{"iss": ""}), "iss"},
			"nested signed_metadata": {testJWT(t, hs256, map[string]any{
				"iss": "https://pdp.example.com", "signed_metadata": "a.b.c",
			}), "signed_metadata claim"},
		} {
			_, err := factory.Validate(nil, signedMetadataConfig(t, "", tc.jwt))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: want an error containing %q, got %v", name, tc.wantErr, err)
			}
		}
	})

	t.Run("claims that disagree with the config are rejected", func(t *testing.T) {
		// A PEP that supports signed metadata MUST prefer the signed values,
		// so a mismatch would make it act on something the plugin does not do.
		for name, tc := range map[string]struct {
			extra   string
			claims  map[string]any
			wantErr string
		}{
			"capabilities differ": {
				`"capabilities": ["urn:a"]`,
				map[string]any{"capabilities": []string{"urn:b"}},
				"claim capabilities",
			},
			"capabilities signed but unconfigured": {
				``,
				map[string]any{"capabilities": []string{"urn:a"}},
				"claim capabilities",
			},
			"capabilities not strings": {
				`"capabilities": ["urn:a"]`,
				map[string]any{"capabilities": []any{1}},
				"array of strings",
			},
			"capabilities null": {
				``,
				map[string]any{"capabilities": nil},
				"array of strings",
			},
			"supported_obligations differ": {
				`"supported_obligations": ["step-up"]`,
				map[string]any{"supported_obligations": []string{"notification"}},
				"claim supported_obligations",
			},
			"access_request_endpoint differs": {
				`"access_request_endpoint": "https://a.example.com/requests"`,
				map[string]any{"access_request_endpoint": "https://b.example.com/requests"},
				"claim access_request_endpoint",
			},
			"access_request_endpoint null": {
				``,
				map[string]any{"access_request_endpoint": nil},
				"must be a string",
			},
			"jwks_uri signed but unconfigured": {
				``,
				map[string]any{"jwks_uri": "https://pdp.example.com/jwks"},
				"claim jwks_uri",
			},
			"jwks_uri not a string": {
				``,
				map[string]any{"jwks_uri": 42},
				"must be a string",
			},
			"search endpoint signed but disabled": {
				``,
				map[string]any{"search_action_endpoint": "https://pdp.example.com/access/v1/search/action"},
				"not configured",
			},
			"search endpoint not a string": {
				`"search": {"subject": "subjects"}`,
				map[string]any{"search_subject_endpoint": 7},
				"must be a string",
			},
		} {
			tc.claims["iss"] = "https://pdp.example.com"
			jwt := testJWT(t, hs256, tc.claims)
			_, err := factory.Validate(nil, signedMetadataConfig(t, tc.extra, jwt))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: want an error containing %q, got %v", name, tc.wantErr, err)
			}
		}
	})

	t.Run("whitespace-only is normalized to unset", func(t *testing.T) {
		result, err := factory.Validate(nil, []byte(`{"signed_metadata": "   "}`))
		if err != nil {
			t.Fatalf("Validate should treat a blank value as unset: %v", err)
		}
		if got := result.(*internal.Config).SignedMetadata; got != "" {
			t.Errorf("expected a blank value to normalize to unset, got %q", got)
		}
	})
}
