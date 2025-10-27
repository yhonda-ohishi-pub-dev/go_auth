# Cloudflare Auth Worker - Go クライアント実装計画書

## 概要
Cloudflare Worker 公開鍵認証システムに対応するGoクライアントライブラリの実装計画。
RSA公開鍵認証を使用してチャレンジ-レスポンス方式で認証を行い、Secret変数を安全に取得する。

## 目的
- Cloudflare Workerの公開鍵認証APIに接続するGoクライアントを実装
- RSA秘密鍵でチャレンジに署名し、認証後にSecret変数を取得
- 再利用可能で使いやすいライブラリとして提供

## アーキテクチャ

### プロジェクト構造
```
go_auth/
├── cmd/
│   └── example/
│       └── main.go              # サンプル実装
├── pkg/
│   ├── authclient/
│   │   ├── client.go            # メインクライアント実装
│   │   ├── auth.go              # 認証ロジック（署名生成）
│   │   ├── types.go             # 型定義
│   │   └── errors.go            # エラー定義
│   └── keygen/
│       ├── keygen.go            # 鍵生成機能
│       └── keygen_test.go       # 鍵生成テスト
├── internal/
│   └── crypto/
│       └── rsa.go               # RSA署名処理
├── testdata/
│   ├── private.pem              # テスト用秘密鍵
│   └── public.pem               # テスト用公開鍵
├── go.mod
├── go.sum
├── README.md
└── IMPLEMENTATION_PLAN.md       # この計画書
```

## 実装フェーズ

### Phase 1: プロジェクト初期化と型定義
**タスク:**
1. Goモジュールの初期化（`go mod init`）
2. 型定義の実装（`types.go`）
   - `ChallengeResponse` - チャレンジレスポンス
   - `VerifyResponse` - 認証成功レスポンス
   - `ErrorResponse` - エラーレスポンス
   - `ClientConfig` - クライアント設定

**成果物:**
- `go.mod`
- `pkg/authclient/types.go`
- `pkg/authclient/errors.go`

### Phase 2: 鍵生成機能の実装
**タスク:**
1. RSA鍵ペア生成機能（2048/4096ビット対応）
2. 秘密鍵のPEM形式保存
3. 公開鍵のPEM形式保存（Cloudflare Worker登録用）
4. 鍵の読み込み機能

**実装詳細:**
- `crypto/rsa`と`crypto/rand`を使用して鍵ペア生成
- `crypto/x509`でPKCS#8形式（秘密鍵）とPKIX形式（公開鍵）に変換
- `encoding/pem`でPEM形式にエンコード
- ファイルパーミッション設定（秘密鍵: 0600、公開鍵: 0644）

**API例:**
```go
// 鍵ペア生成
privateKey, err := keygen.GeneratePrivateKey(2048)
publicKey := &privateKey.PublicKey

// PEM形式に変換
privatePEM, err := keygen.EncodePrivateKeyToPEM(privateKey)
publicPEM, err := keygen.EncodePublicKeyToPEM(publicKey)

// ファイルに保存
err = keygen.SavePrivateKey("private.pem", privateKey)
err = keygen.SavePublicKey("public.pem", publicKey)

// ワンライナー
err = keygen.GenerateAndSaveKeyPair("private.pem", "public.pem", 2048)
```

**成果物:**
- `pkg/keygen/keygen.go`
- `pkg/keygen/keygen_test.go`

### Phase 3: RSA署名機能の実装
**タスク:**
1. RSA秘密鍵の読み込み機能（PEM形式）
2. チャレンジへの署名生成（RSASSA-PKCS1-v1_5 + SHA-256）
3. Base64エンコード処理

**実装詳細:**
- `crypto/rsa`と`crypto/x509`パッケージを使用
- PEM形式の秘密鍵ファイルから`*rsa.PrivateKey`を生成
- `rsa.SignPKCS1v15`でSHA-256ハッシュに署名
- 署名をBase64エンコードして返す

**成果物:**
- `internal/crypto/rsa.go`
- `pkg/authclient/auth.go`

### Phase 4: HTTPクライアントの実装
**タスク:**
1. クライアント構造体の実装
2. `/challenge`エンドポイントへのリクエスト
3. `/verify`エンドポイントへのリクエスト
4. `/health`エンドポイントへのリクエスト（オプション）

**実装詳細:**
```go
type Client struct {
    BaseURL    string
    ClientID   string
    PrivateKey *rsa.PrivateKey
    HTTPClient *http.Client
}

// 認証フロー
func (c *Client) Authenticate() (*VerifyResponse, error)
// 1. RequestChallenge() - チャレンジ取得
// 2. SignChallenge() - チャレンジに署名
// 3. VerifySignature() - 署名を送信して認証
```

**成果物:**
- `pkg/authclient/client.go`

### Phase 5: エラーハンドリングとリトライロジック
**タスク:**
1. カスタムエラー型の定義
2. HTTPステータスコードに応じたエラー処理
3. リトライロジック（オプション）
   - チャレンジ期限切れ時の自動再取得
   - ネットワークエラー時のリトライ

**エラー種類:**
- `ErrUnauthorized` - 認証失敗（401）
- `ErrBadRequest` - リクエスト不正（400）
- `ErrNotFound` - エンドポイント未発見（404）
- `ErrInternalServer` - サーバーエラー（500）
- `ErrChallengeExpired` - チャレンジ期限切れ
- `ErrInvalidSignature` - 署名検証失敗

**成果物:**
- `pkg/authclient/errors.go`（拡充）

### Phase 6: サンプル実装とドキュメント
**タスク:**
1. サンプルアプリケーションの作成
2. README.mdの作成
3. コード内ドキュメント（godoc形式）

**サンプル内容:**
```go
func main() {
    // 初回: 鍵ペアを生成
    err := keygen.GenerateAndSaveKeyPair("private.pem", "public.pem", 2048)
    if err != nil {
        log.Fatal(err)
    }

    // 公開鍵を表示（Cloudflare Workerに登録）
    publicPEM, _ := os.ReadFile("public.pem")
    fmt.Printf("公開鍵をCloudflare Workerに登録してください:\n%s\n", publicPEM)

    // 認証クライアント作成
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
    fmt.Printf("認証成功!\n")
    fmt.Printf("Token: %s\n", resp.Token)
    fmt.Printf("Secrets: %+v\n", resp.SecretData)
}
```

**成果物:**
- `cmd/example/main.go`
- `README.md`

### Phase 7: テストの実装
**タスク:**
1. ユニットテストの作成
   - RSA鍵生成機能のテスト
   - RSA署名機能のテスト
   - エラーハンドリングのテスト
2. 統合テスト（モックサーバー使用）
   - チャレンジ取得のテスト
   - 署名検証のテスト
3. テスト用の鍵ペア生成（keygenパッケージを使用）

**成果物:**
- `pkg/keygen/keygen_test.go`
- `pkg/authclient/client_test.go`
- `pkg/authclient/auth_test.go`
- `internal/crypto/rsa_test.go`
- `testdata/private.pem`
- `testdata/public.pem`

## 技術仕様

### 暗号化仕様
- **アルゴリズム**: RSA
- **署名方式**: RSASSA-PKCS1-v1_5
- **ハッシュ関数**: SHA-256
- **鍵長**: 2048ビット以上推奨
- **エンコーディング**: Base64

### API エンドポイント

#### POST /challenge
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
**リクエスト:**
```json
{
  "clientId": "unique-client-identifier",
  "challenge": "base64-encoded-random-bytes",
  "signature": "base64-encoded-signature"
}
```

**レスポンス（成功）:**
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

### 依存パッケージ
- 標準ライブラリのみ使用（外部依存なし）
  - `crypto/rsa` - RSA鍵生成・署名
  - `crypto/rand` - 暗号学的乱数生成
  - `crypto/sha256` - SHA-256ハッシュ
  - `crypto/x509` - X.509証明書・鍵のエンコード/デコード
  - `encoding/pem` - PEM形式のエンコード/デコード
  - `encoding/base64` - Base64エンコード/デコード
  - `encoding/json` - JSON処理
  - `net/http` - HTTPクライアント

## セキュリティ考慮事項

### 秘密鍵の管理
- 秘密鍵はファイルシステムから読み込み
- 環境変数やSecrets Managerからのロードもサポート（オプション）
- メモリ上の秘密鍵は適切にゼロクリア（可能な範囲で）

### チャレンジの検証
- チャレンジは一度のみ使用（使い捨て）
- 期限切れチャレンジは自動再取得

### 通信セキュリティ
- HTTPS必須（HTTPSでない場合は警告）
- TLS証明書の検証

## 使用例

### 1. 鍵ペアの生成
```go
package main

import (
    "fmt"
    "log"

    "github.com/yourusername/go_auth/pkg/keygen"
)

func main() {
    // RSA鍵ペア生成（2048ビット）
    err := keygen.GenerateAndSaveKeyPair("private.pem", "public.pem", 2048)
    if err != nil {
        log.Fatal(err)
    }

    // 公開鍵を読み込んで表示（Cloudflare Workerに登録用）
    publicPEM, err := keygen.LoadPublicKeyPEM("public.pem")
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("以下の公開鍵をCloudflare Workerに登録してください:\n%s\n", publicPEM)
}
```

### 2. 基本的な認証
```go
package main

import (
    "fmt"
    "log"

    "github.com/yourusername/go_auth/pkg/authclient"
)

func main() {
    // クライアント作成
    client, err := authclient.NewClientFromFile(
        "https://your-worker.workers.dev",
        "your-client-id",
        "path/to/private.pem",
    )
    if err != nil {
        log.Fatal(err)
    }

    // 認証
    resp, err := client.Authenticate()
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("認証成功!\n")
    fmt.Printf("Token: %s\n", resp.Token)
    fmt.Printf("Secret Data: %+v\n", resp.SecretData)
}
```

### 3. リトライ付き認証
```go
client.SetRetry(3, time.Second*2) // 最大3回、2秒間隔
resp, err := client.Authenticate()
```

## テスト計画

### ユニットテスト
- RSA鍵ペア生成の正確性（2048/4096ビット）
- PEM形式の鍵の保存と読み込み
- RSA署名生成の正確性
- Base64エンコーディング
- エラーハンドリング

### 統合テスト
- モックHTTPサーバーを使用
- チャレンジ-レスポンスフローの完全なテスト
- エラーシナリオのテスト

### E2Eテスト（オプション）
- 実際のCloudflare Workerに対するテスト
- テスト環境の準備が必要

## マイルストーン

| Phase | 期間 | 成果物 |
|-------|------|--------|
| Phase 1 | 1日 | 型定義、プロジェクト構造 |
| Phase 2 | 1-2日 | 鍵生成機能 |
| Phase 3 | 1-2日 | RSA署名機能 |
| Phase 4 | 2-3日 | HTTPクライアント実装 |
| Phase 5 | 1-2日 | エラーハンドリング |
| Phase 6 | 1日 | サンプルとドキュメント |
| Phase 7 | 2-3日 | テスト実装 |

**合計**: 9-14日

## 今後の拡張可能性

### v1.0以降の機能
- トークンキャッシング（再認証の削減）
- コンテキストサポート（タイムアウト、キャンセル）
- ログ出力のカスタマイズ
- メトリクス収集
- 複数クライアントIDのサポート
- 鍵ローテーション機能

### オプション機能
- 環境変数からの設定読み込み
- AWS Secrets Manager統合
- Kubernetes Secrets統合
- gRPCサポート

## 参考資料

### Cloudflare Auth Worker
- Repository: https://github.com/yhonda-ohishi/cloudflare-auth-worker
- SPEC.md: 詳細仕様
- README.md: API仕様

### Go標準ライブラリ
- crypto/rsa: https://pkg.go.dev/crypto/rsa
- crypto/x509: https://pkg.go.dev/crypto/x509
- encoding/pem: https://pkg.go.dev/encoding/pem

## 次のステップ

1. ✅ この計画書のレビューと承認
2. ⬜ Phase 1の開始（プロジェクト初期化）
3. ⬜ Phase 2の開始（鍵生成機能 - 最初に実装することでテスト用鍵も生成可能）
4. ⬜ Phase 3-7の順次実装

---

**作成日**: 2025-10-28
**バージョン**: 1.1
**更新内容**: 鍵生成機能をライブラリとして追加（Phase 2として挿入）
