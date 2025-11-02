package authmiddleware

import (
	"net/http"
	"strings"
)

// Config はミドルウェアの設定
type Config struct {
	// GetAccessToken は現在のアクセストークンを取得する関数
	GetAccessToken func() string

	// WhitelistPaths は認証をスキップするパスのリスト
	WhitelistPaths []string

	// RequireTunnel がtrueの場合、Cloudflare Tunnelからのリクエストのみ許可
	RequireTunnel bool
}

// TunnelAuthMiddleware はCloudflare Tunnel経由のBearer認証ミドルウェア
type TunnelAuthMiddleware struct {
	config Config
}

// NewTunnelAuthMiddleware は新しいミドルウェアを作成します
func NewTunnelAuthMiddleware(config Config) *TunnelAuthMiddleware {
	return &TunnelAuthMiddleware{
		config: config,
	}
}

// Middleware はHTTPミドルウェアハンドラを返します
func (m *TunnelAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORSプリフライトリクエスト（OPTIONS）は認証をスキップ
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		// ホワイトリストパスのチェック
		if m.isWhitelisted(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Cloudflare Tunnel判定
		if m.config.RequireTunnel && !m.isFromCloudflare(r) {
			http.Error(w, "Access denied: not from Cloudflare Tunnel", http.StatusForbidden)
			return
		}

		// Bearer トークン認証
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Bearer トークンの抽出
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// トークンの検証
		expectedToken := m.config.GetAccessToken()
		if expectedToken == "" {
			http.Error(w, "Server authentication not initialized", http.StatusInternalServerError)
			return
		}

		if token != expectedToken {
			http.Error(w, "Invalid access token", http.StatusUnauthorized)
			return
		}

		// 認証成功
		next.ServeHTTP(w, r)
	})
}

// isWhitelisted はパスがホワイトリストに含まれるかチェックします
func (m *TunnelAuthMiddleware) isWhitelisted(path string) bool {
	for _, whitelistPath := range m.config.WhitelistPaths {
		if path == whitelistPath || strings.HasPrefix(path, whitelistPath) {
			return true
		}
	}
	return false
}

// isFromCloudflare はリクエストがCloudflare Tunnelから来ているかチェックします
func (m *TunnelAuthMiddleware) isFromCloudflare(r *http.Request) bool {
	// Cloudflare-Cdn-Loop ヘッダーの存在をチェック
	cdnLoop := r.Header.Get("Cloudflare-Cdn-Loop")
	return cdnLoop != ""
}
