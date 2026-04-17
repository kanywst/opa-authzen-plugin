package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

type todo struct {
	ID      string `json:"id"`
	Title   string `json:"title"`
	OwnerID string `json:"ownerID"`
}

type user struct {
	ID    string   `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

var todos = []todo{
	{ID: "todo-1", Title: "Destroy the Galactic Federation", OwnerID: "rick@the-citadel.com"},
	{ID: "todo-2", Title: "Pass math class", OwnerID: "morty@the-citadel.com"},
	{ID: "todo-3", Title: "Get a summer job", OwnerID: "summer@the-smiths.com"},
}

var users = map[string]user{
	"rick":   {ID: "rick", Email: "rick@the-citadel.com", Roles: []string{"admin", "evil_genius"}},
	"morty":  {ID: "morty", Email: "morty@the-citadel.com", Roles: []string{"editor"}},
	"summer": {ID: "summer", Email: "summer@the-smiths.com", Roles: []string{"editor"}},
	"beth":   {ID: "beth", Email: "beth@the-smiths.com", Roles: []string{"viewer"}},
	"jerry":  {ID: "jerry", Email: "jerry@the-smiths.com", Roles: []string{"viewer"}},
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/todos", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, todos)
		case http.MethodPost:
			writeJSON(w, http.StatusCreated, todo{ID: "todo-new", Title: "New todo", OwnerID: "unknown"})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/todos/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/todos/")
		if id == "" {
			http.Error(w, "missing id", http.StatusBadRequest)
			return
		}
		switch r.Method {
		case http.MethodGet:
			for _, t := range todos {
				if t.ID == id {
					writeJSON(w, http.StatusOK, t)
					return
				}
			}
			http.Error(w, "not found", http.StatusNotFound)
		case http.MethodPut:
			writeJSON(w, http.StatusOK, todo{ID: id, Title: "Updated", OwnerID: "unknown"})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/users/")
		if u, ok := users[id]; ok {
			writeJSON(w, http.StatusOK, u)
		} else {
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	http.ListenAndServe(":8080", mux) //nolint:errcheck
}
