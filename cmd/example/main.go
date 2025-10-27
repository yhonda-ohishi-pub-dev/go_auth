package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/yhonda-ohishi/go_auth/pkg/authclient"
	"github.com/yhonda-ohishi/go_auth/pkg/keygen"
)

func main() {
	// コマンドラインフラグ
	var (
		generateKeys = flag.Bool("generate-keys", false, "Generate RSA key pair")
		privateFile  = flag.String("private-key", "private.pem", "Path to private key file")
		publicFile   = flag.String("public-key", "public.pem", "Path to public key file")
		keyBits      = flag.Int("key-bits", 2048, "RSA key size (2048 or 4096)")
		baseURL      = flag.String("url", "", "Cloudflare Worker base URL")
		clientID     = flag.String("client-id", "", "Client ID")
		maxRetries   = flag.Int("retries", 0, "Maximum number of retries")
		retryBackoff = flag.Duration("retry-backoff", 2*time.Second, "Retry backoff duration")
	)

	flag.Parse()

	// 鍵生成モード
	if *generateKeys {
		fmt.Println("Generating RSA key pair...")
		if err := keygen.GenerateAndSaveKeyPair(*privateFile, *publicFile, *keyBits); err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		fmt.Printf("✓ Private key saved to: %s\n", *privateFile)
		fmt.Printf("✓ Public key saved to: %s\n", *publicFile)

		// 公開鍵を表示
		publicPEM, err := os.ReadFile(*publicFile)
		if err != nil {
			log.Fatalf("Failed to read public key: %v", err)
		}

		fmt.Println("\n--- Public Key ---")
		fmt.Println("Copy this public key and register it in your Cloudflare Worker:")
		fmt.Println(string(publicPEM))
		return
	}

	// 認証モード
	if *baseURL == "" || *clientID == "" {
		fmt.Println("Error: -url and -client-id are required for authentication")
		flag.Usage()
		os.Exit(1)
	}

	// 秘密鍵ファイルの存在確認
	if _, err := os.Stat(*privateFile); os.IsNotExist(err) {
		fmt.Printf("Error: Private key file not found: %s\n", *privateFile)
		fmt.Println("Run with -generate-keys to create a new key pair")
		os.Exit(1)
	}

	fmt.Printf("Authenticating to: %s\n", *baseURL)
	fmt.Printf("Client ID: %s\n", *clientID)
	fmt.Printf("Private key: %s\n", *privateFile)

	// クライアント作成
	client, err := authclient.NewClientFromFile(*baseURL, *clientID, *privateFile)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	// リトライ設定
	if *maxRetries > 0 {
		fmt.Printf("Max retries: %d (backoff: %v)\n", *maxRetries, *retryBackoff)
		client.SetRetry(*maxRetries, *retryBackoff)
	}

	// ヘルスチェック（オプション）
	fmt.Println("\nChecking server health...")
	health, err := client.Health()
	if err != nil {
		log.Printf("Warning: Health check failed: %v", err)
	} else {
		fmt.Printf("✓ Server status: %s\n", health.Status)
	}

	// 認証実行
	fmt.Println("\nAuthenticating...")
	resp, err := client.Authenticate()
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// 結果表示
	fmt.Println("\n✓ Authentication successful!")
	fmt.Printf("\nToken: %s\n", resp.Token)
	fmt.Println("\nSecret Data:")
	for key, value := range resp.SecretData {
		fmt.Printf("  %s: %s\n", key, value)
	}
}
