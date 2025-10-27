package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	// ErrInvalidKeySize は鍵サイズが不正な場合のエラー
	ErrInvalidKeySize = errors.New("invalid key size: must be 2048 or 4096")

	// ErrInvalidPEMBlock はPEMブロックが不正な場合のエラー
	ErrInvalidPEMBlock = errors.New("invalid PEM block")

	// ErrInvalidKeyType は鍵の型が不正な場合のエラー
	ErrInvalidKeyType = errors.New("invalid key type")
)

// GeneratePrivateKey は指定されたビット数のRSA秘密鍵を生成します
func GeneratePrivateKey(bits int) (*rsa.PrivateKey, error) {
	if bits != 2048 && bits != 4096 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidKeySize, bits)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	return privateKey, nil
}

// EncodePrivateKeyToPEM は秘密鍵をPEM形式にエンコードします
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// PKCS#8形式にエンコード
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// PEMブロックを作成
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}

// EncodePublicKeyToPEM は公開鍵をPEM形式にエンコードします
func EncodePublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	if publicKey == nil {
		return nil, errors.New("public key is nil")
	}

	// PKIX形式にエンコード
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	// PEMブロックを作成
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return publicKeyPEM, nil
}

// SavePrivateKey は秘密鍵をファイルに保存します（パーミッション: 0600）
func SavePrivateKey(filename string, privateKey *rsa.PrivateKey) error {
	privateKeyPEM, err := EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		return err
	}

	// 0600パーミッションで保存（所有者のみ読み書き可能）
	if err := os.WriteFile(filename, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key file: %w", err)
	}

	return nil
}

// SavePublicKey は公開鍵をファイルに保存します（パーミッション: 0644）
func SavePublicKey(filename string, publicKey *rsa.PublicKey) error {
	publicKeyPEM, err := EncodePublicKeyToPEM(publicKey)
	if err != nil {
		return err
	}

	// 0644パーミッションで保存（所有者: 読み書き、その他: 読み取りのみ）
	if err := os.WriteFile(filename, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key file: %w", err)
	}

	return nil
}

// GenerateAndSaveKeyPair は鍵ペアを生成してファイルに保存します
func GenerateAndSaveKeyPair(privateKeyFile, publicKeyFile string, bits int) error {
	// 秘密鍵を生成
	privateKey, err := GeneratePrivateKey(bits)
	if err != nil {
		return err
	}

	// 秘密鍵を保存
	if err := SavePrivateKey(privateKeyFile, privateKey); err != nil {
		return err
	}

	// 公開鍵を保存
	if err := SavePublicKey(publicKeyFile, &privateKey.PublicKey); err != nil {
		return err
	}

	return nil
}

// LoadPrivateKey はPEMファイルから秘密鍵を読み込みます
func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	return ParsePrivateKeyPEM(pemData)
}

// LoadPublicKey はPEMファイルから公開鍵を読み込みます
func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	return ParsePublicKeyPEM(pemData)
}

// LoadPublicKeyPEM はPEMファイルから公開鍵を文字列として読み込みます
func LoadPublicKeyPEM(filename string) (string, error) {
	pemData, err := os.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("failed to read public key file: %w", err)
	}

	return string(pemData), nil
}

// ParsePrivateKeyPEM はPEMデータから秘密鍵をパースします
func ParsePrivateKeyPEM(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidPEMBlock
	}

	// PKCS#8形式をパース
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// PKCS#1形式も試す
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}

	// *rsa.PrivateKey型にキャスト
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *rsa.PrivateKey, got %T", ErrInvalidKeyType, key)
	}

	return rsaKey, nil
}

// ParsePublicKeyPEM はPEMデータから公開鍵をパースします
func ParsePublicKeyPEM(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, ErrInvalidPEMBlock
	}

	// PKIX形式をパース
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// *rsa.PublicKey型にキャスト
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: expected *rsa.PublicKey, got %T", ErrInvalidKeyType, pub)
	}

	return rsaPub, nil
}
