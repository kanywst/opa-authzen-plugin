package internal

import (
	"bytes"
	"context"
	"net/http/httptest"
	"testing"
)

func BenchmarkEvaluationAllow(b *testing.B) {
	p := testPlugin(&testing.T{}, module)
	p.Start(context.Background())
	defer p.Stop(context.Background())

	body := `{
		"subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
		"action": {"name": "delete"},
		"resource": {"type": "document", "id": "doc-123"}
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/access/v1/evaluation", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		p.handleEvaluation(w, req)
		if w.Code != 200 {
			b.Fatalf("unexpected status code: %d", w.Code)
		}
	}
}

func BenchmarkEvaluationDeny(b *testing.B) {
	p := testPlugin(&testing.T{}, module)
	p.Start(context.Background())
	defer p.Stop(context.Background())

	body := `{
		"subject": {"type": "user", "id": "bob"},
		"action": {"name": "delete"},
		"resource": {"type": "document", "id": "doc-123"}
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/access/v1/evaluation", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		p.handleEvaluation(w, req)
		if w.Code != 200 {
			b.Fatalf("unexpected status code: %d", w.Code)
		}
	}
}

func BenchmarkBatchEvaluations(b *testing.B) {
	p := testPlugin(&testing.T{}, module)
	p.Start(context.Background())
	defer p.Stop(context.Background())

	body := `{
		"subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
		"action": {"name": "read"},
		"evaluations": [
			{"resource": {"type": "document", "id": "doc-1"}},
			{"resource": {"type": "document", "id": "doc-2"}},
			{"resource": {"type": "document", "id": "doc-3"}},
			{"resource": {"type": "document", "id": "doc-4"}},
			{"resource": {"type": "document", "id": "doc-5"}}
		]
	}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/access/v1/evaluations", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		p.handleEvaluations(w, req)
		if w.Code != 200 {
			b.Fatalf("unexpected status code: %d", w.Code)
		}
	}
}

func BenchmarkWellKnown(b *testing.B) {
	p := testPlugin(&testing.T{}, module)
	p.Start(context.Background())
	defer p.Stop(context.Background())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("GET", "/.well-known/authzen-configuration", nil)
		w := httptest.NewRecorder()

		p.handleWellKnown(w, req)
		if w.Code != 200 {
			b.Fatalf("unexpected status code: %d", w.Code)
		}
	}
}

func BenchmarkParallelEvaluations(b *testing.B) {
	p := testPlugin(&testing.T{}, module)
	p.Start(context.Background())
	defer p.Stop(context.Background())

	body := `{
		"subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
		"action": {"name": "read"},
		"resource": {"type": "document", "id": "doc-123"}
	}`

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			req := httptest.NewRequest("POST", "/access/v1/evaluation", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			p.handleEvaluation(w, req)
			if w.Code != 200 {
				b.Fatalf("unexpected status code: %d", w.Code)
			}
		}
	})
}
