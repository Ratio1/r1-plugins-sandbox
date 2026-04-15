package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	cstoremock "github.com/Ratio1/r1-plugins-sandbox/mock/cstore"
)

func TestHandleCStoreHSync(t *testing.T) {
	store := cstoremock.New()
	ctx := context.Background()
	if err := cstoremock.HSet(ctx, store, "players", "a", map[string]any{"score": 3}, nil); err != nil {
		t.Fatalf("HSet players/a: %v", err)
	}
	if err := cstoremock.HSet(ctx, store, "players", "b", map[string]any{"score": 7}, nil); err != nil {
		t.Fatalf("HSet players/b: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/hsync", strings.NewReader(`{"hkey":"players"}`))
	rec := httptest.NewRecorder()

	handleCStoreHSync(rec, req, store)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Result struct {
			HashKey      string `json:"hkey"`
			SourcePeer   string `json:"source_peer"`
			MergedFields int    `json:"merged_fields"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Result.HashKey != "players" || payload.Result.SourcePeer != "mock-local" || payload.Result.MergedFields != 2 {
		t.Fatalf("unexpected result: %#v", payload.Result)
	}
}

func TestHandleCStoreHSyncUsesFirstPeer(t *testing.T) {
	store := cstoremock.New()
	ctx := context.Background()
	if err := cstoremock.HSet(ctx, store, "players", "a", map[string]any{"score": 3}, nil); err != nil {
		t.Fatalf("HSet players/a: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/hsync",
		strings.NewReader(`{"hkey":"players","chainstore_peers":["peer-a","peer-b"]}`),
	)
	rec := httptest.NewRecorder()

	handleCStoreHSync(rec, req, store)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Result struct {
			SourcePeer string `json:"source_peer"`
		} `json:"result"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Result.SourcePeer != "peer-a" {
		t.Fatalf("expected source_peer peer-a, got %q", payload.Result.SourcePeer)
	}
}

func TestHandleCStoreHSyncValidation(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		body       string
		wantStatus int
		wantMsg    string
	}{
		{
			name:       "method not allowed",
			method:     http.MethodGet,
			body:       "",
			wantStatus: http.StatusMethodNotAllowed,
			wantMsg:    "method not allowed",
		},
		{
			name:       "invalid json",
			method:     http.MethodPost,
			body:       "{",
			wantStatus: http.StatusBadRequest,
			wantMsg:    "invalid JSON payload",
		},
		{
			name:       "missing hkey",
			method:     http.MethodPost,
			body:       `{"hkey":"   "}`,
			wantStatus: http.StatusBadRequest,
			wantMsg:    "hkey is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/hsync", strings.NewReader(tc.body))
			rec := httptest.NewRecorder()

			handleCStoreHSync(rec, req, cstoremock.New())

			if rec.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tc.wantStatus, rec.Body.String())
			}
			var payload struct {
				Error struct {
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.NewDecoder(rec.Body).Decode(&payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload.Error.Message != tc.wantMsg {
				t.Fatalf("error.message=%q want=%q", payload.Error.Message, tc.wantMsg)
			}
		})
	}
}
