package authclient

import (
	"crypto/rsa"
	"net/http"
	"time"
)

// ClientConfig はクライアントの設定
type ClientConfig struct {
	// BaseURL はCloudflare WorkerのベースURL (例: https://your-worker.workers.dev)
	BaseURL string

	// ClientID はクライアント識別子
	ClientID string

	// PrivateKey はRSA秘密鍵
	PrivateKey *rsa.PrivateKey

	// HTTPClient はカスタムHTTPクライアント（オプション）
	HTTPClient *http.Client

	// Timeout はリクエストタイムアウト（デフォルト: 30秒）
	Timeout time.Duration
}

// ChallengeResponse はチャレンジエンドポイントからのレスポンス
type ChallengeResponse struct {
	// Challenge はBase64エンコードされたランダムチャレンジ
	Challenge string `json:"challenge"`

	// ExpiresAt はチャレンジの有効期限（Unix時間）
	ExpiresAt int64 `json:"expiresAt"`
}

// VerifyRequest は署名検証エンドポイントへのリクエスト
type VerifyRequest struct {
	// ClientID はクライアント識別子
	ClientID string `json:"clientId"`

	// Challenge は受け取ったチャレンジ
	Challenge string `json:"challenge"`

	// Signature はBase64エンコードされた署名
	Signature string `json:"signature"`
}

// VerifyResponse は署名検証エンドポイントからのレスポンス
type VerifyResponse struct {
	// Success は認証成功フラグ
	Success bool `json:"success"`

	// Token はJWTトークン
	Token string `json:"token"`

	// SecretData はSecret変数のマップ
	SecretData map[string]string `json:"secretData"`

	// Error はエラーメッセージ（認証失敗時）
	Error string `json:"error,omitempty"`
}

// ErrorResponse はエラーレスポンス
type ErrorResponse struct {
	// Error はエラーメッセージ
	Error string `json:"error"`

	// Success は常にfalse
	Success bool `json:"success"`
}

// HealthResponse はヘルスチェックのレスポンス
type HealthResponse struct {
	// Status はステータス（通常 "ok"）
	Status string `json:"status"`
}
