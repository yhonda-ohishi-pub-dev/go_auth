package authclient

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internalcrypto "github.com/yhonda-ohishi/go_auth/internal/crypto"
)

func setupTestServer(t *testing.T, privateKey *rsa.PrivateKey) *httptest.Server {
	publicKey := &privateKey.PublicKey

	mux := http.NewServeMux()

	// POST /challenge
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if req["clientId"] == "" {
			http.Error(w, "Missing clientId", http.StatusBadRequest)
			return
		}

		resp := ChallengeResponse{
			Challenge: "test-challenge-12345",
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// POST /verify
	mux.HandleFunc("/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		if req.ClientID == "" || req.Challenge == "" || req.Signature == "" {
			http.Error(w, "Missing fields", http.StatusBadRequest)
			return
		}

		// 署名を検証
		err := internalcrypto.VerifySignature(publicKey, req.Challenge, req.Signature)
		if err != nil {
			resp := ErrorResponse{
				Success: false,
				Error:   "Invalid signature",
			}
			w.WriteHeader(http.StatusUnauthorized)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
			return
		}

		resp := VerifyResponse{
			Success: true,
			Token:   "test-jwt-token",
			SecretData: map[string]string{
				"SECRET_DATA": "test-secret",
				"API_KEY":     "test-api-key",
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	// GET /health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		resp := HealthResponse{
			Status: "ok",
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return httptest.NewServer(mux)
}

func TestNewClient(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	tests := []struct {
		name    string
		config  ClientConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: ClientConfig{
				BaseURL:    "https://test.example.com",
				ClientID:   "test-client",
				PrivateKey: privateKey,
			},
			wantErr: false,
		},
		{
			name: "missing baseURL",
			config: ClientConfig{
				ClientID:   "test-client",
				PrivateKey: privateKey,
			},
			wantErr: true,
		},
		{
			name: "missing clientID",
			config: ClientConfig{
				BaseURL:    "https://test.example.com",
				PrivateKey: privateKey,
			},
			wantErr: true,
		},
		{
			name: "missing privateKey",
			config: ClientConfig{
				BaseURL:  "https://test.example.com",
				ClientID: "test-client",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && client == nil {
				t.Error("NewClient() returned nil client")
			}
		})
	}
}

func TestRequestChallenge(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := setupTestServer(t, privateKey)
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		ClientID:   "test-client",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.RequestChallenge()
	if err != nil {
		t.Errorf("RequestChallenge() error = %v", err)
		return
	}

	if resp.Challenge == "" {
		t.Error("RequestChallenge() returned empty challenge")
	}

	if resp.ExpiresAt == 0 {
		t.Error("RequestChallenge() returned zero expiresAt")
	}
}

func TestVerifySignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := setupTestServer(t, privateKey)
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		ClientID:   "test-client",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// チャレンジに署名
	challenge := "test-challenge-12345"
	signature, err := internalcrypto.SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}

	resp, err := client.VerifySignature(challenge, signature)
	if err != nil {
		t.Errorf("VerifySignature() error = %v", err)
		return
	}

	if !resp.Success {
		t.Error("VerifySignature() success = false, want true")
	}

	if resp.Token == "" {
		t.Error("VerifySignature() returned empty token")
	}

	if len(resp.SecretData) == 0 {
		t.Error("VerifySignature() returned empty secretData")
	}
}

func TestAuthenticate(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := setupTestServer(t, privateKey)
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		ClientID:   "test-client",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.Authenticate()
	if err != nil {
		t.Errorf("Authenticate() error = %v", err)
		return
	}

	if !resp.Success {
		t.Error("Authenticate() success = false, want true")
	}

	if resp.Token == "" {
		t.Error("Authenticate() returned empty token")
	}

	if len(resp.SecretData) == 0 {
		t.Error("Authenticate() returned empty secretData")
	}
}

func TestHealth(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	server := setupTestServer(t, privateKey)
	defer server.Close()

	client, err := NewClient(ClientConfig{
		BaseURL:    server.URL,
		ClientID:   "test-client",
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	resp, err := client.Health()
	if err != nil {
		t.Errorf("Health() error = %v", err)
		return
	}

	if resp.Status != "ok" {
		t.Errorf("Health() status = %s, want ok", resp.Status)
	}
}
