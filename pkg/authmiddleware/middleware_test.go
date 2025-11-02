package authmiddleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTunnelAuthMiddleware_Middleware(t *testing.T) {
	// テスト用のハンドラ
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	t.Run("OPTIONSリクエストは認証をスキップ", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		// OPTIONSリクエストはAuthorizationヘッダーなしでも通過
		req := httptest.NewRequest("OPTIONS", "/api/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}

		if rec.Body.String() != "success" {
			t.Errorf("Expected body 'success', got '%s'", rec.Body.String())
		}
	})

	t.Run("認証成功", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer test-token-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}

		if rec.Body.String() != "success" {
			t.Errorf("Expected body 'success', got '%s'", rec.Body.String())
		}
	})

	t.Run("Authorizationヘッダーなし", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})

	t.Run("不正なAuthorizationヘッダー形式", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Basic test-token-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})

	t.Run("不正なトークン", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", rec.Code)
		}
	})

	t.Run("ホワイトリストパス", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{"/health", "/public"},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		// ホワイトリストパスは認証なしでアクセス可能
		req := httptest.NewRequest("GET", "/health", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})

	t.Run("ホワイトリストパス（プレフィックスマッチ）", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{"/public"},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		// /public/xxx もホワイトリスト対象
		req := httptest.NewRequest("GET", "/public/api/test", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})

	t.Run("Cloudflare Tunnel必須（Cloudflareヘッダーあり）", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  true,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer test-token-123")
		req.Header.Set("Cloudflare-Cdn-Loop", "cloudflare")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", rec.Code)
		}
	})

	t.Run("Cloudflare Tunnel必須（Cloudflareヘッダーなし）", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "test-token-123" },
			WhitelistPaths: []string{},
			RequireTunnel:  true,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer test-token-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("Expected status 403, got %d", rec.Code)
		}
	})

	t.Run("アクセストークンが初期化されていない", func(t *testing.T) {
		config := Config{
			GetAccessToken: func() string { return "" },
			WhitelistPaths: []string{},
			RequireTunnel:  false,
		}

		middleware := NewTunnelAuthMiddleware(config)
		handler := middleware.Middleware(testHandler)

		req := httptest.NewRequest("GET", "/api/test", nil)
		req.Header.Set("Authorization", "Bearer test-token-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", rec.Code)
		}
	})
}

func TestTunnelAuthMiddleware_isWhitelisted(t *testing.T) {
	config := Config{
		GetAccessToken: func() string { return "test-token" },
		WhitelistPaths: []string{"/health", "/public", "/api/v1/status"},
		RequireTunnel:  false,
	}

	middleware := NewTunnelAuthMiddleware(config)

	tests := []struct {
		path     string
		expected bool
	}{
		{"/health", true},
		{"/public", true},
		{"/public/api", true},
		{"/api/v1/status", true},
		{"/api/v1/status/details", true},
		{"/api/test", false},
		{"/private", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := middleware.isWhitelisted(tt.path)
			if result != tt.expected {
				t.Errorf("isWhitelisted(%s) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestTunnelAuthMiddleware_isFromCloudflare(t *testing.T) {
	config := Config{
		GetAccessToken: func() string { return "test-token" },
		WhitelistPaths: []string{},
		RequireTunnel:  true,
	}

	middleware := NewTunnelAuthMiddleware(config)

	tests := []struct {
		name     string
		headers  map[string]string
		expected bool
	}{
		{
			name:     "Cloudflare-Cdn-Loopヘッダーあり",
			headers:  map[string]string{"Cloudflare-Cdn-Loop": "cloudflare"},
			expected: true,
		},
		{
			name:     "Cloudflare-Cdn-Loopヘッダーなし",
			headers:  map[string]string{},
			expected: false,
		},
		{
			name:     "他のヘッダーのみ",
			headers:  map[string]string{"User-Agent": "test"},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/test", nil)
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			result := middleware.isFromCloudflare(req)
			if result != tt.expected {
				t.Errorf("isFromCloudflare() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
