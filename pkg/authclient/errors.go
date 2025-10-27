package authclient

import (
	"errors"
	"fmt"
)

var (
	// ErrUnauthorized は認証失敗エラー（401）
	ErrUnauthorized = errors.New("authentication failed: unauthorized")

	// ErrBadRequest はリクエスト不正エラー（400）
	ErrBadRequest = errors.New("bad request: invalid parameters")

	// ErrNotFound はエンドポイント未発見エラー（404）
	ErrNotFound = errors.New("endpoint not found")

	// ErrInternalServer はサーバーエラー（500）
	ErrInternalServer = errors.New("internal server error")

	// ErrChallengeExpired はチャレンジ期限切れエラー
	ErrChallengeExpired = errors.New("challenge expired")

	// ErrInvalidSignature は署名検証失敗エラー
	ErrInvalidSignature = errors.New("invalid signature")

	// ErrInvalidConfig は設定不正エラー
	ErrInvalidConfig = errors.New("invalid client configuration")

	// ErrInvalidPrivateKey は秘密鍵不正エラー
	ErrInvalidPrivateKey = errors.New("invalid private key")

	// ErrNetworkError はネットワークエラー
	ErrNetworkError = errors.New("network error")
)

// HTTPError はHTTPステータスコードを含むエラー
type HTTPError struct {
	StatusCode int
	Message    string
	Err        error
}

func (e *HTTPError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("HTTP %d: %s (%v)", e.StatusCode, e.Message, e.Err)
	}
	return fmt.Sprintf("HTTP %d: %s", e.StatusCode, e.Message)
}

func (e *HTTPError) Unwrap() error {
	return e.Err
}

// NewHTTPError はHTTPErrorを作成
func NewHTTPError(statusCode int, message string, err error) *HTTPError {
	return &HTTPError{
		StatusCode: statusCode,
		Message:    message,
		Err:        err,
	}
}
