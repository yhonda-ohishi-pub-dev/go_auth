package authclient

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/yhonda-ohishi-pub-dev/go_auth/pkg/keygen"
)

// Client はCloudflare Auth Workerに接続するクライアント
type Client struct {
	baseURL      string
	clientID     string
	privateKey   *rsa.PrivateKey
	httpClient   *http.Client
	timeout      time.Duration
	maxRetries   int
	retryBackoff time.Duration
	secretKeys   []string
	repoUrl      string
	grpcEndpoint string
}

// NewClient は新しいクライアントを作成します
func NewClient(config ClientConfig) (*Client, error) {
	if config.BaseURL == "" {
		return nil, fmt.Errorf("%w: baseURL is required", ErrInvalidConfig)
	}

	if config.ClientID == "" {
		return nil, fmt.Errorf("%w: clientID is required", ErrInvalidConfig)
	}

	if config.PrivateKey == nil {
		return nil, fmt.Errorf("%w: privateKey is required", ErrInvalidConfig)
	}

	// デフォルトのHTTPクライアントを使用
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	// デフォルトのタイムアウトを設定
	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	httpClient.Timeout = timeout

	// HTTPSチェック
	if !strings.HasPrefix(config.BaseURL, "https://") && !strings.HasPrefix(config.BaseURL, "http://localhost") {
		fmt.Fprintf(io.Discard, "WARNING: BaseURL is not HTTPS: %s\n", config.BaseURL)
	}

	return &Client{
		baseURL:      strings.TrimSuffix(config.BaseURL, "/"),
		clientID:     config.ClientID,
		privateKey:   config.PrivateKey,
		httpClient:   httpClient,
		timeout:      timeout,
		maxRetries:   0, // デフォルトはリトライなし
		retryBackoff: 2 * time.Second,
		secretKeys:   config.SecretKeys,
		repoUrl:      config.RepoUrl,
		grpcEndpoint: config.GrpcEndpoint,
	}, nil
}

// NewClientFromFile はファイルから秘密鍵を読み込んでクライアントを作成します
func NewClientFromFile(baseURL, clientID, privateKeyFile string) (*Client, error) {
	privateKey, err := keygen.LoadPrivateKey(privateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return NewClient(ClientConfig{
		BaseURL:    baseURL,
		ClientID:   clientID,
		PrivateKey: privateKey,
	})
}

// SetRetry はリトライ設定を行います
func (c *Client) SetRetry(maxRetries int, backoff time.Duration) {
	c.maxRetries = maxRetries
	c.retryBackoff = backoff
}

// Authenticate は認証フローを実行します
// 1. チャレンジを取得
// 2. チャレンジに署名
// 3. 署名を送信して認証
func (c *Client) Authenticate() (*VerifyResponse, error) {
	return c.authenticateWithRetry(c.maxRetries)
}

// authenticateWithRetry はリトライ付き認証を実行します
func (c *Client) authenticateWithRetry(retriesLeft int) (*VerifyResponse, error) {
	// チャレンジを取得
	challengeResp, err := c.RequestChallenge()
	if err != nil {
		if retriesLeft > 0 && c.isRetryable(err) {
			time.Sleep(c.retryBackoff)
			return c.authenticateWithRetry(retriesLeft - 1)
		}
		return nil, fmt.Errorf("failed to request challenge: %w", err)
	}

	// チャレンジに署名
	signature, err := c.signChallenge(challengeResp.Challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to sign challenge: %w", err)
	}

	// 署名を送信して認証
	verifyResp, err := c.VerifySignature(challengeResp.Challenge, signature)
	if err != nil {
		if retriesLeft > 0 && c.isRetryable(err) {
			time.Sleep(c.retryBackoff)
			return c.authenticateWithRetry(retriesLeft - 1)
		}
		return nil, fmt.Errorf("failed to verify signature: %w", err)
	}

	return verifyResp, nil
}

// isRetryable はエラーがリトライ可能かどうかを判定します
func (c *Client) isRetryable(err error) bool {
	// ネットワークエラーはリトライ可能
	if errors.Is(err, ErrNetworkError) {
		return true
	}

	// HTTPエラーの場合、ステータスコードで判定
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		// 5xxエラーはリトライ可能
		if httpErr.StatusCode >= 500 && httpErr.StatusCode < 600 {
			return true
		}
		// 429 Too Many Requestsもリトライ可能
		if httpErr.StatusCode == 429 {
			return true
		}
	}

	return false
}

// RequestChallenge はチャレンジを取得します
func (c *Client) RequestChallenge() (*ChallengeResponse, error) {
	url := fmt.Sprintf("%s/challenge", c.baseURL)

	// リクエストボディを作成
	reqBody := map[string]string{
		"clientId": c.clientID,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// HTTPリクエストを作成
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// リクエストを送信
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	// レスポンスボディを読み込み
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// ステータスコードをチェック
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleHTTPError(resp.StatusCode, body)
	}

	// レスポンスをパース
	var challengeResp ChallengeResponse
	if err := json.Unmarshal(body, &challengeResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &challengeResp, nil
}

// VerifySignature は署名を検証してSecret変数を取得します
func (c *Client) VerifySignature(challenge, signature string) (*VerifyResponse, error) {
	url := fmt.Sprintf("%s/verify", c.baseURL)

	// リクエストボディを作成
	reqBody := VerifyRequest{
		ClientID:     c.clientID,
		Challenge:    challenge,
		Signature:    signature,
		RepoUrl:      c.repoUrl,
		GrpcEndpoint: c.grpcEndpoint,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// HTTPリクエストを作成
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// リクエストを送信
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	// レスポンスボディを読み込み
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// ステータスコードをチェック
	if resp.StatusCode != http.StatusOK {
		return nil, c.handleHTTPError(resp.StatusCode, body)
	}

	// レスポンスをパース
	var verifyResp VerifyResponse
	if err := json.Unmarshal(body, &verifyResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// 認証失敗チェック
	if !verifyResp.Success {
		return nil, fmt.Errorf("%w: %s", ErrUnauthorized, verifyResp.Error)
	}

	// SecretKeysが指定されている場合、フィルタリング
	if len(c.secretKeys) > 0 {
		filteredData := make(map[string]string)
		for _, key := range c.secretKeys {
			if value, ok := verifyResp.SecretData[key]; ok {
				filteredData[key] = value
			}
		}
		verifyResp.SecretData = filteredData
	}

	return &verifyResp, nil
}

// Health はヘルスチェックを実行します
func (c *Client) Health() (*HealthResponse, error) {
	url := fmt.Sprintf("%s/health", c.baseURL)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNetworkError, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleHTTPError(resp.StatusCode, body)
	}

	var healthResp HealthResponse
	if err := json.Unmarshal(body, &healthResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &healthResp, nil
}

// handleHTTPError はHTTPエラーを処理します
func (c *Client) handleHTTPError(statusCode int, body []byte) error {
	// エラーレスポンスをパース
	var errResp ErrorResponse
	if err := json.Unmarshal(body, &errResp); err != nil {
		// パース失敗時はステータスコードのみでエラーを返す
		return NewHTTPError(statusCode, string(body), nil)
	}

	// ステータスコードに応じたエラーを返す
	var baseErr error
	switch statusCode {
	case http.StatusBadRequest:
		baseErr = ErrBadRequest
	case http.StatusUnauthorized:
		baseErr = ErrUnauthorized
	case http.StatusNotFound:
		baseErr = ErrNotFound
	case http.StatusInternalServerError:
		baseErr = ErrInternalServer
	default:
		baseErr = fmt.Errorf("HTTP error %d", statusCode)
	}

	return NewHTTPError(statusCode, errResp.Error, baseErr)
}
