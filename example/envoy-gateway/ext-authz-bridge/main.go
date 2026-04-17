// ext-authz-bridge translates Envoy ext_authz gRPC requests into AuthZEN
// Access Evaluation API calls (Section 6). It acts as a thin protocol bridge
// between the API gateway and any AuthZEN-compliant PDP.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	auth_pb "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_type "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

// authZENRequest is the AuthZEN Access Evaluation request (Section 6.1).
type authZENRequest struct {
	Subject  map[string]any `json:"subject"`
	Action   map[string]any `json:"action"`
	Resource map[string]any `json:"resource"`
}

// authZENResponse is the AuthZEN Access Evaluation response (Section 6.2).
type authZENResponse struct {
	Decision bool `json:"decision"`
}

type server struct {
	pdpURL     string
	httpClient *http.Client
}

func (s *server) Check(ctx context.Context, req *auth_pb.CheckRequest) (*auth_pb.CheckResponse, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	method := httpReq.GetMethod()
	path := httpReq.GetPath()
	headers := httpReq.GetHeaders()

	// Extract user from X-User header.
	userID := headers["x-user"]
	if userID == "" {
		log.Printf("denied: missing X-User header")
		return denied(http.StatusForbidden, `{"error":"missing X-User header"}`), nil
	}

	// Map HTTP method + path to AuthZEN action and resource.
	action, resourceType, resourceID := mapRoute(method, path)
	if action == "" {
		log.Printf("denied: unmapped route %s %s", method, path)
		return denied(http.StatusForbidden, `{"error":"unmapped route"}`), nil
	}

	// Build AuthZEN request.
	azReq := authZENRequest{
		Subject:  map[string]any{"type": "user", "id": userID},
		Action:   map[string]any{"name": action},
		Resource: map[string]any{"type": resourceType, "id": resourceID},
	}

	decision, err := s.evaluate(ctx, azReq)
	if err != nil {
		log.Printf("error: PDP evaluation failed: %v", err)
		return denied(http.StatusForbidden, `{"error":"authorization check failed"}`), nil
	}

	if !decision {
		log.Printf("denied: user=%s action=%s resource=%s/%s", userID, action, resourceType, resourceID)
		return denied(http.StatusForbidden, `{"error":"forbidden"}`), nil
	}

	log.Printf("allowed: user=%s action=%s resource=%s/%s", userID, action, resourceType, resourceID)
	return allowed(), nil
}

// mapRoute translates HTTP method + path into an AuthZEN action name and resource.
func mapRoute(method, path string) (action, resourceType, resourceID string) {
	// Strip query string.
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}
	path = strings.TrimSuffix(path, "/")

	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 0 {
		return "", "", ""
	}

	switch parts[0] {
	case "users":
		return "can_read_user", "user", idOrCollection(parts)
	case "todos":
		id := idOrCollection(parts)
		switch method {
		case "GET":
			return "can_read_todos", "todo", id
		case "POST":
			return "can_create_todo", "todo", id
		case "PUT", "PATCH":
			return "can_update_todo", "todo", id
		case "DELETE":
			return "can_delete_todo", "todo", id
		}
	}
	return "", "", ""
}

func idOrCollection(parts []string) string {
	if len(parts) >= 2 {
		return parts[1]
	}
	return parts[0]
}

// evaluate sends the AuthZEN request to the PDP.
func (s *server) evaluate(ctx context.Context, azReq authZENRequest) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	body, err := json.Marshal(azReq)
	if err != nil {
		return false, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.pdpURL+"/access/v1/evaluation", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	var azResp authZENResponse
	if err := json.NewDecoder(resp.Body).Decode(&azResp); err != nil {
		return false, fmt.Errorf("decode response: %w", err)
	}
	return azResp.Decision, nil
}

func denied(code int32, body string) *auth_pb.CheckResponse {
	return &auth_pb.CheckResponse{
		Status: &status.Status{Code: code},
		HttpResponse: &auth_pb.CheckResponse_DeniedResponse{
			DeniedResponse: &auth_pb.DeniedHttpResponse{
				Status: &envoy_type.HttpStatus{
					Code: envoy_type.StatusCode(code),
				},
				Body: body,
			},
		},
	}
}

func allowed() *auth_pb.CheckResponse {
	return &auth_pb.CheckResponse{
		Status: &status.Status{Code: int32(codes.OK)},
		HttpResponse: &auth_pb.CheckResponse_OkResponse{
			OkResponse: &auth_pb.OkHttpResponse{},
		},
	}
}

func main() {
	pdpURL := os.Getenv("AUTHZEN_PDP_URL")
	if pdpURL == "" {
		pdpURL = "http://localhost:8181"
	}

	lis, err := net.Listen("tcp", "0.0.0.0:3001")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	auth_pb.RegisterAuthorizationServer(s, &server{
		pdpURL:     pdpURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	})

	log.Printf("ext-authz-bridge listening on :3001, PDP=%s", pdpURL)
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
