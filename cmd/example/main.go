package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/yhonda-ohishi-pub-dev/go_auth/pkg/authclient"
	"github.com/yhonda-ohishi-pub-dev/go_auth/pkg/keygen"
)

func main() {
	// コマンドラインフラグ
	var (
		generateKeys = flag.Bool("generate-keys", false, "Generate RSA key pair")
		privateFile  = flag.String("private-key", "private.pem", "Path to private key file")
		publicFile   = flag.String("public-key", "public.pem", "Path to public key file")
		keyBits      = flag.Int("key-bits", 2048, "RSA key size (2048 or 4096)")
		baseURL      = flag.String("url", "", "Cloudflare Worker base URL")
		clientID     = flag.String("client-id", "testclient", "Client ID")
		maxRetries   = flag.Int("retries", 0, "Maximum number of retries")
		retryBackoff = flag.Duration("retry-backoff", 2*time.Second, "Retry backoff duration")
		saveEnv      = flag.Bool("save-env", false, "Save secrets to .env file")
		envFile      = flag.String("env-file", ".env", "Path to .env file")
		secretKeys      = flag.String("secret-keys", "", "Comma-separated list of secret keys to retrieve (empty for all)")
		repoUrl         = flag.String("repo-url", "", "GitHub repository URL (optional)")
		grpcEndpoint    = flag.String("grpc-endpoint", "", "gRPC endpoint URL (optional)")
		includeRepoList = flag.Bool("include-repo-list", false, "Include repository URL list in response")
	)

	flag.Parse()

	// 鍵生成モード
	if *generateKeys {
		// clientIDが必須
		if *clientID == "" {
			fmt.Println("Error: -client-id is required for key generation")
			flag.Usage()
			os.Exit(1)
		}

		fmt.Println("Generating RSA key pair...")

		// 鍵ペアとCloudflare設定ファイルを生成
		if err := keygen.GenerateAndSaveKeyPair(*privateFile, *publicFile, *clientID, *keyBits); err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		fmt.Printf("✓ Private key saved to: %s\n", *privateFile)
		fmt.Printf("✓ Public key saved to: %s\n", *publicFile)

		// Cloudflare設定ファイルの内容を表示
		configFile := *publicFile + ".cloudflare.json"
		fmt.Printf("✓ Cloudflare config saved to: %s\n", configFile)

		configContent, err := os.ReadFile(configFile)
		if err != nil {
			log.Fatalf("Failed to read config file: %v", err)
		}

		fmt.Println("\n--- Cloudflare Worker Configuration ---")
		fmt.Println("Copy this JSON to your Cloudflare Worker's AUTHORIZED_CLIENTS variable:")
		fmt.Println(string(configContent))

		// 公開鍵を表示
		publicPEM, err := os.ReadFile(*publicFile)
		if err != nil {
			log.Fatalf("Failed to read public key: %v", err)
		}

		fmt.Println("\n--- Public Key (PEM format) ---")
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
	if *repoUrl != "" {
		fmt.Printf("Repository URL: %s\n", *repoUrl)
	}
	if *grpcEndpoint != "" {
		fmt.Printf("gRPC Endpoint: %s\n", *grpcEndpoint)
	}

	// 秘密鍵を読み込み
	privateKey, err := keygen.LoadPrivateKey(*privateFile)
	if err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// SecretKeysをパース
	var secretKeyList []string
	if *secretKeys != "" {
		for _, key := range strings.Split(*secretKeys, ",") {
			secretKeyList = append(secretKeyList, strings.TrimSpace(key))
		}
		fmt.Printf("Secret keys filter: %v\n", secretKeyList)
	}

	// クライアント作成
	client, err := authclient.NewClient(authclient.ClientConfig{
		BaseURL:         *baseURL,
		ClientID:        *clientID,
		PrivateKey:      privateKey,
		SecretKeys:      secretKeyList,
		RepoUrl:         *repoUrl,
		GrpcEndpoint:    *grpcEndpoint,
		IncludeRepoList: *includeRepoList,
	})
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

	// RepoListを表示
	if len(resp.RepoList) > 0 {
		fmt.Println("\nRepository List:")
		for i, repo := range resp.RepoList {
			fmt.Printf("  %d. %s\n", i+1, repo)
		}
	}

	// .envファイルに保存
	if *saveEnv {
		if err := resp.SaveToEnvFile(*envFile); err != nil {
			log.Fatalf("Failed to save .env file: %v", err)
		}
		fmt.Printf("\n✓ Secrets saved to: %s\n", *envFile)
	}
}
