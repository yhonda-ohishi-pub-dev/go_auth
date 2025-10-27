package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// SignChallenge はチャレンジに署名してBase64エンコードした文字列を返します
// RSASSA-PKCS1-v1_5 + SHA-256を使用
func SignChallenge(privateKey *rsa.PrivateKey, challenge string) (string, error) {
	if privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	if challenge == "" {
		return "", fmt.Errorf("challenge is empty")
	}

	// チャレンジをSHA-256でハッシュ化
	hashed := sha256.Sum256([]byte(challenge))

	// RSASSA-PKCS1-v1_5で署名
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign challenge: %w", err)
	}

	// Base64エンコード
	signatureBase64 := base64.StdEncoding.EncodeToString(signature)

	return signatureBase64, nil
}

// VerifySignature は署名を検証します（テスト用）
func VerifySignature(publicKey *rsa.PublicKey, challenge string, signatureBase64 string) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}

	if challenge == "" {
		return fmt.Errorf("challenge is empty")
	}

	if signatureBase64 == "" {
		return fmt.Errorf("signature is empty")
	}

	// Base64デコード
	signature, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	// チャレンジをSHA-256でハッシュ化
	hashed := sha256.Sum256([]byte(challenge))

	// 署名検証
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}
