package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The AuthZEN working group publishes JSON Schemas for the Access Evaluation
// request and response (openid/authzen, api/schemas). The repository carries
// no license, so the schemas are not vendored here: `make test-contract`
// fetches them at a pinned commit and points AUTHZEN_SPEC_DIR at the checkout.
// Without it these tests skip.
const specDirEnv = "AUTHZEN_SPEC_DIR"

type specSchemas struct {
	dir      string
	request  *jsonschema.Schema
	response *jsonschema.Schema
}

func loadSpecSchemas(t *testing.T) specSchemas {
	t.Helper()
	dir := os.Getenv(specDirEnv)
	if dir == "" {
		t.Skipf("%s not set; run `make test-contract` to check against the published AuthZEN schemas", specDirEnv)
	}

	c := jsonschema.NewCompiler()
	compile := func(name string) *jsonschema.Schema {
		path := filepath.Join(dir, "api", "schemas", name)
		s, err := c.Compile(path)
		if err != nil {
			t.Fatalf("compile %s: %v", path, err)
		}
		return s
	}
	return specSchemas{
		dir:      dir,
		request:  compile("evaluation-request.schema.json"),
		response: compile("evaluation-response.schema.json"),
	}
}

func decodeForSchema(t *testing.T, raw []byte) any {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
	return v
}

// specRequestExamples returns the request schema's own `examples` plus every
// single-evaluation request from the interop Todo decision file, so the
// corpus of known-valid requests comes from the working group, not from us.
func specRequestExamples(t *testing.T, dir string) map[string]json.RawMessage {
	t.Helper()
	out := map[string]json.RawMessage{}

	var schema struct {
		Examples []json.RawMessage `json:"examples"`
	}
	readJSON(t, filepath.Join(dir, "api", "schemas", "evaluation-request.schema.json"), &schema)
	for i, ex := range schema.Examples {
		out["schema-example-"+strconv.Itoa(i)] = ex
	}

	var decisions struct {
		Evaluation []struct {
			Request json.RawMessage `json:"request"`
		} `json:"evaluation"`
	}
	readJSON(t, filepath.Join(dir, "interop", "authzen-todo-backend", "test", "decisions-authorization-api-1_0-02.json"), &decisions)
	for i, d := range decisions.Evaluation {
		out["interop-todo-"+strconv.Itoa(i)] = d.Request
	}

	if len(out) == 0 {
		t.Fatal("no example requests found in the spec checkout")
	}
	return out
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// TestSpecSchemaRequestAgreement checks that the plugin and the published
// request schema agree on which Access Evaluation requests are valid (Section
// 6.1): a request the schema accepts must get a 200 whose body satisfies the
// response schema, and a request the schema rejects must get a 400.
func TestSpecSchemaRequestAgreement(t *testing.T) {
	s := loadSpecSchemas(t)
	p := testContextPlugin(t, decisionContextModule)

	type tc struct {
		body string
		// lenient marks a request the schema rejects but the plugin
		// deliberately accepts. Each one needs a reason.
		lenient string
	}
	cases := map[string]tc{
		"missing subject":          {body: `{"resource":{"type":"doc","id":"1"},"action":{"name":"read"}}`},
		"missing resource":         {body: `{"subject":{"type":"user","id":"alice"},"action":{"name":"read"}}`},
		"missing action":           {body: `{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc","id":"1"}}`},
		"subject not an object":    {body: `{"subject":"alice","resource":{"type":"doc","id":"1"},"action":{"name":"read"}}`},
		"subject missing type":     {body: `{"subject":{"id":"alice"},"resource":{"type":"doc","id":"1"},"action":{"name":"read"}}`},
		"subject id not a string":  {body: `{"subject":{"type":"user","id":42},"resource":{"type":"doc","id":"1"},"action":{"name":"read"}}`},
		"resource missing id":      {body: `{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc"},"action":{"name":"read"}}`},
		"resource type not string": {body: `{"subject":{"type":"user","id":"alice"},"resource":{"type":["doc"],"id":"1"},"action":{"name":"read"}}`},
		"action missing name":      {body: `{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc","id":"1"},"action":{}}`},
		"properties is an array":   {body: `{"subject":{"type":"user","id":"alice","properties":[]},"resource":{"type":"doc","id":"1"},"action":{"name":"read"}}`},
		"context is a string":      {body: `{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc","id":"1"},"action":{"name":"read"},"context":"now"}`},
		"extra top-level member":   {body: `{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc","id":"1"},"action":{"name":"read"},"x-trace":"abc"}`},
		"all properties objects": {body: `{"subject":{"type":"user","id":"alice","properties":{"department":"Sales"}},` +
			`"resource":{"type":"doc","id":"1","properties":{}},"action":{"name":"read","properties":{"method":"GET"}},"context":{}}`},
		"null properties": {
			body:    `{"subject":{"type":"user","id":"alice","properties":null},"resource":{"type":"doc","id":"1"},"action":{"name":"read"}}`,
			lenient: "a JSON null member is treated as absent, the same as for subject/resource/action",
		},
		"null context": {
			body:    `{"subject":{"type":"user","id":"alice"},"resource":{"type":"doc","id":"1"},"action":{"name":"read"},"context":null}`,
			lenient: "a JSON null member is treated as absent, the same as for subject/resource/action",
		},
	}
	for name, raw := range specRequestExamples(t, s.dir) {
		cases[name] = tc{body: string(raw)}
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			schemaErr := s.request.Validate(decodeForSchema(t, []byte(c.body)))
			w := postEvaluation(p, c.body)

			switch {
			case schemaErr == nil && c.lenient != "":
				t.Fatalf("marked lenient but the schema accepts it; drop the marker")
			case schemaErr == nil:
				if w.Code != http.StatusOK {
					t.Fatalf("schema accepts the request but the plugin returned %d: %s", w.Code, w.Body.String())
				}
				if err := s.response.Validate(decodeForSchema(t, w.Body.Bytes())); err != nil {
					t.Fatalf("response %s does not satisfy the response schema: %v", w.Body.String(), err)
				}
			case c.lenient != "":
				if w.Code != http.StatusOK {
					t.Fatalf("expected the lenient path (%s) to return 200, got %d: %s", c.lenient, w.Code, w.Body.String())
				}
			default:
				if w.Code != http.StatusBadRequest {
					t.Fatalf("schema rejects the request (%v) but the plugin returned %d: %s", schemaErr, w.Code, w.Body.String())
				}
			}
		})
	}
}

// TestSpecSchemaBatchResponses checks that every element of an Access
// Evaluations response is a Decision in the sense of the published response
// schema (Section 7.2), including the per-item error form and items that
// carry a decision context.
func TestSpecSchemaBatchResponses(t *testing.T) {
	s := loadSpecSchemas(t)

	bodies := map[string]string{
		"plain": `{
			"subject": {"type": "user", "id": "alice"},
			"action": {"name": "read"},
			"evaluations": [
				{"resource": {"type": "doc", "id": "1"}},
				{"resource": {"type": "doc", "id": "2"}, "subject": {"type": "user", "id": "bob"}}
			]
		}`,
		"item error": `{
			"subject": {"type": "user", "id": "alice"},
			"evaluations": [
				{"resource": {"type": "doc", "id": "1"}, "action": {"name": "read"}},
				{"resource": {"type": "doc", "id": "2"}}
			]
		}`,
		"deny_on_first_deny": `{
			"resource": {"type": "doc", "id": "1"},
			"action": {"name": "read"},
			"evaluations": [
				{"subject": {"type": "user", "id": "alice"}},
				{"subject": {"type": "user", "id": "bob"}},
				{"subject": {"type": "user", "id": "carol"}}
			],
			"options": {"evaluations_semantic": "deny_on_first_deny"}
		}`,
	}
	plugins := map[string]*AuthZenPlugin{
		"without decision context": testPlugin(t, decisionContextModule),
		"with decision context":    testContextPlugin(t, decisionContextModule),
	}

	for pname, p := range plugins {
		for bname, body := range bodies {
			t.Run(pname+"/"+bname, func(t *testing.T) {
				w := postEvaluations(p, body)
				if w.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
				}
				var resp struct {
					Evaluations []json.RawMessage `json:"evaluations"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatal(err)
				}
				if len(resp.Evaluations) == 0 {
					t.Fatalf("no evaluations in %s", w.Body.String())
				}
				for i, item := range resp.Evaluations {
					if err := s.response.Validate(decodeForSchema(t, item)); err != nil {
						t.Errorf("evaluations[%d] %s does not satisfy the response schema: %v", i, item, err)
					}
				}
			})
		}
	}
}
