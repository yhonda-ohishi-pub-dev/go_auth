# go_auth

Goクライアントライブラリfor [Cloudflare Auth Worker](https://github.com/yhonda-ohishi/cloudflare-auth-worker)

RSA公開鍵認証を使用してCloudflare Workerに安全に接続し、Secret変数を取得するGoクライアントライブラリです。

## 特徴

- 🔐 RSA公開鍵認証（RSASSA-PKCS1-v1_5 + SHA-256）
- 🔑 チャレンジ-レスポンス認証方式
- 🔄 自動リトライ機能
- 📦 標準ライブラリのみ（外部依存なし）
- ⚡ シンプルで使いやすいAPI
- 🧪 包括的なテストカバレッジ

## インストール

```bash
go get github.com/yhonda-ohishi-pub-dev/go_auth
```

## クイックスタート

### 1. 鍵ペアの生成

```bash
go run cmd/example/main.go -generate-keys
```

これにより以下のファイルが生成されます：
- `private.pem` - 秘密鍵（このクライアントで使用）
- `public.pem` - 公開鍵（Cloudflare Workerに登録）

生成された公開鍵をCloudflare Workerの`wrangler.toml`に登録してください。

### 2. 認証の実行

```bash
go run cmd/example/main.go \
  -url https://your-worker.workers.dev \
  -client-id your-client-id
```

## 使用方法

### ライブラリとして使用

```go
package main

import (
    "fmt"
    "log"

    "github.com/yhonda-ohishi-pub-dev/go_auth/pkg/authclient"
)

func main() {
    // クライアント作成
    client, err := authclient.NewClientFromFile(
        "https://your-worker.workers.dev",
        "your-client-id",
        "private.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // 認証実行
    resp, err := client.Authenticate()
    if err != nil {
        log.Fatal(err)
    }

    // Secret変数の取得
    fmt.Printf("Token: %s\n", resp.Token)
    for key, value := range resp.SecretData {
        fmt.Printf("%s: %s\n", key, value)
    }
}
```

### リトライ機能の使用

```go
// リトライ設定（最大3回、2秒間隔）
client.SetRetry(3, 2*time.Second)

resp, err := client.Authenticate()
```

### 認証ミドルウェアの使用

```go
package main

import (
    "log"
    "net/http"

    "github.com/yhonda-ohishi-pub-dev/go_auth/pkg/authclient"
    "github.com/yhonda-ohishi-pub-dev/go_auth/pkg/authmiddleware"
)

func main() {
    // 認証クライアント作成
    client, err := authclient.NewClientFromFile(
        "https://your-worker.workers.dev",
        "your-client-id",
        "private.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // 初回認証
    if _, err := client.Authenticate(); err != nil {
        log.Fatal(err)
    }

    // ミドルウェア設定
    middleware := authmiddleware.NewTunnelAuthMiddleware(authmiddleware.Config{
        GetAccessToken: client.GetAccessToken,
        WhitelistPaths: []string{"/health", "/public"},
        RequireTunnel:  true, // Cloudflare Tunnel経由のみ許可
    })

    // ハンドラ登録
    mux := http.NewServeMux()
    mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Protected data"))
    })
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("OK"))
    })

    // ミドルウェアを適用
    handler := middleware.Middleware(mux)

    log.Println("Server starting on :8080")
    if err := http.ListenAndServe(":8080", handler); err != nil {
        log.Fatal(err)
    }
}
```

### 鍵生成APIの使用

```go
package main

import (
    "fmt"
    "log"

    "github.com/yhonda-ohishi-pub-dev/go_auth/pkg/keygen"
)

func main() {
    // RSA鍵ペア生成（2048ビット）
    err := keygen.GenerateAndSaveKeyPair("private.pem", "public.pem", 2048)
    if err != nil {
        log.Fatal(err)
    }

    // 公開鍵を読み込んで表示
    publicPEM, err := keygen.LoadPublicKeyPEM("public.pem")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Public Key:\n%s\n", publicPEM)
}
```

## CLIツール

### コマンドラインオプション

```
Usage of example:
  -client-id string
        Client ID
  -generate-keys
        Generate RSA key pair
  -key-bits int
        RSA key size (2048 or 4096) (default 2048)
  -private-key string
        Path to private key file (default "private.pem")
  -public-key string
        Path to public key file (default "public.pem")
  -retries int
        Maximum number of retries (default 0)
  -retry-backoff duration
        Retry backoff duration (default 2s)
  -url string
        Cloudflare Worker base URL
```

### 使用例

#### 鍵ペア生成

```bash
# 2048ビット鍵を生成
go run cmd/example/main.go -generate-keys

# 4096ビット鍵を生成
go run cmd/example/main.go -generate-keys -key-bits 4096

# カスタムファイル名で生成
go run cmd/example/main.go -generate-keys \
  -private-key my-private.pem \
  -public-key my-public.pem
```

#### 認証

```bash
# 基本的な認証
go run cmd/example/main.go \
  -url https://your-worker.workers.dev \
  -client-id your-client-id

# リトライ付き認証
go run cmd/example/main.go \
  -url https://your-worker.workers.dev \
  -client-id your-client-id \
  -retries 3 \
  -retry-backoff 5s

# カスタム秘密鍵ファイルを使用
go run cmd/example/main.go \
  -url https://your-worker.workers.dev \
  -client-id your-client-id \
  -private-key my-private.pem
```

## API仕様

### Cloudflare Worker エンドポイント

このライブラリは以下のエンドポイントを使用します：

#### POST /challenge
チャレンジを取得

**リクエスト:**
```json
{
  "clientId": "unique-client-identifier"
}
```

**レスポンス:**
```json
{
  "challenge": "base64-encoded-random-bytes",
  "expiresAt": 1234567890
}
```

#### POST /verify
署名を検証

**リクエスト:**
```json
{
  "clientId": "unique-client-identifier",
  "challenge": "base64-encoded-random-bytes",
  "signature": "base64-encoded-signature"
}
```

**レスポンス:**
```json
{
  "success": true,
  "token": "jwt-token",
  "secretData": {
    "SECRET_DATA": "機密情報",
    "API_KEY": "APIキー"
  }
}
```

#### GET /health
ヘルスチェック

**レスポンス:**
```json
{
  "status": "ok"
}
```

## パッケージ構成

### pkg/authclient
認証クライアントの実装

**主要な型:**
- `Client` - HTTPクライアント
- `ClientConfig` - クライアント設定
- `ChallengeResponse` - チャレンジレスポンス
- `VerifyResponse` - 認証成功レスポンス

**主要な関数:**
- `NewClient(config ClientConfig) (*Client, error)` - クライアント作成
- `NewClientFromFile(baseURL, clientID, privateKeyFile string) (*Client, error)` - ファイルから作成
- `Authenticate() (*VerifyResponse, error)` - 認証実行
- `SetRetry(maxRetries int, backoff time.Duration)` - リトライ設定

### pkg/keygen
RSA鍵生成・管理機能

**主要な関数:**
- `GeneratePrivateKey(bits int) (*rsa.PrivateKey, error)` - 秘密鍵生成
- `GenerateAndSaveKeyPair(privateFile, publicFile string, bits int) error` - 鍵ペア生成・保存
- `LoadPrivateKey(filename string) (*rsa.PrivateKey, error)` - 秘密鍵読み込み
- `LoadPublicKey(filename string) (*rsa.PublicKey, error)` - 公開鍵読み込み

### pkg/authmiddleware
HTTPミドルウェア機能

**主要な型:**
- `Config` - ミドルウェア設定
- `TunnelAuthMiddleware` - 認証ミドルウェア

**主要な関数:**
- `NewTunnelAuthMiddleware(config Config) *TunnelAuthMiddleware` - ミドルウェア作成
- `Middleware(next http.Handler) http.Handler` - HTTPミドルウェアハンドラ

## セキュリティ

### 暗号化仕様
- **アルゴリズム**: RSA
- **署名方式**: RSASSA-PKCS1-v1_5
- **ハッシュ関数**: SHA-256
- **鍵長**: 2048ビット以上推奨

### 秘密鍵の管理
- 秘密鍵ファイルは0600パーミッションで保存されます
- 秘密鍵は決してネットワーク経由で送信されません
- チャレンジは一度のみ使用（使い捨て）

### HTTPS
- 本番環境では必ずHTTPSを使用してください
- ローカル開発以外でHTTPを使用すると警告が表示されます

## テスト

```bash
# 全てのテストを実行
go test ./...

# カバレッジ付きテスト
go test -cover ./...

# 詳細出力
go test -v ./...

# 特定のパッケージのみ
go test ./pkg/authclient
go test ./pkg/keygen
go test ./internal/crypto
```

## プロジェクト構造

```
go_auth/
├── cmd/
│   └── example/
│       └── main.go              # サンプルCLIアプリケーション
├── pkg/
│   ├── authclient/
│   │   ├── client.go            # HTTPクライアント実装
│   │   ├── auth.go              # 認証ロジック
│   │   ├── types.go             # 型定義
│   │   ├── errors.go            # エラー定義
│   │   ├── env.go               # .env保存機能
│   │   └── client_test.go       # テスト
│   ├── keygen/
│   │   ├── keygen.go            # 鍵生成機能
│   │   └── keygen_test.go       # テスト
│   └── authmiddleware/
│       ├── middleware.go        # HTTPミドルウェア
│       └── middleware_test.go   # テスト
├── internal/
│   └── crypto/
│       ├── rsa.go               # RSA署名処理
│       └── rsa_test.go          # テスト
├── testdata/                    # テスト用データ
├── go.mod
├── go.sum
├── README.md
└── IMPLEMENTATION_PLAN.md
```

## トラブルシューティング

### 認証失敗（401 Unauthorized）
- 公開鍵がCloudflare Workerに正しく登録されているか確認
- Client IDが正しいか確認
- 秘密鍵ファイルが正しいか確認

### チャレンジ期限切れ
- ネットワーク遅延が大きい場合、リトライ機能を使用
- システム時刻が正しいか確認

### ネットワークエラー
- Cloudflare WorkerのURLが正しいか確認
- ファイアウォール設定を確認
- リトライ機能を使用（`-retries 3`）

## ライセンス

MIT

## 関連プロジェクト

- [Cloudflare Auth Worker](https://github.com/yhonda-ohishi/cloudflare-auth-worker) - サーバー側実装

## 貢献

Issue・Pull Requestを歓迎します。

## 作者

Generated with Claude Code
