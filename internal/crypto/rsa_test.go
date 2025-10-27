package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSignChallenge(t *testing.T) {
	// テスト用の鍵ペアを生成
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	tests := []struct {
		name       string
		privateKey *rsa.PrivateKey
		challenge  string
		wantErr    bool
	}{
		{
			name:       "valid challenge",
			privateKey: privateKey,
			challenge:  "test-challenge-123",
			wantErr:    false,
		},
		{
			name:       "empty challenge",
			privateKey: privateKey,
			challenge:  "",
			wantErr:    true,
		},
		{
			name:       "nil private key",
			privateKey: nil,
			challenge:  "test-challenge",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := SignChallenge(tt.privateKey, tt.challenge)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignChallenge() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && signature == "" {
				t.Error("SignChallenge() returned empty signature")
			}
		})
	}
}

func TestVerifySignature(t *testing.T) {
	// テスト用の鍵ペアを生成
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 有効な署名を生成
	challenge := "test-challenge-456"
	validSignature, err := SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatalf("failed to sign challenge: %v", err)
	}

	tests := []struct {
		name      string
		publicKey *rsa.PublicKey
		challenge string
		signature string
		wantErr   bool
	}{
		{
			name:      "valid signature",
			publicKey: publicKey,
			challenge: challenge,
			signature: validSignature,
			wantErr:   false,
		},
		{
			name:      "invalid signature",
			publicKey: publicKey,
			challenge: challenge,
			signature: "aW52YWxpZC1zaWduYXR1cmU=",
			wantErr:   true,
		},
		{
			name:      "wrong challenge",
			publicKey: publicKey,
			challenge: "wrong-challenge",
			signature: validSignature,
			wantErr:   true,
		},
		{
			name:      "empty challenge",
			publicKey: publicKey,
			challenge: "",
			signature: validSignature,
			wantErr:   true,
		},
		{
			name:      "empty signature",
			publicKey: publicKey,
			challenge: challenge,
			signature: "",
			wantErr:   true,
		},
		{
			name:      "nil public key",
			publicKey: nil,
			challenge: challenge,
			signature: validSignature,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySignature(tt.publicKey, tt.challenge, tt.signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	// テスト用の鍵ペアを生成
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// チャレンジを署名
	challenge := "integration-test-challenge"
	signature, err := SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatalf("SignChallenge() failed: %v", err)
	}

	// 署名を検証
	err = VerifySignature(publicKey, challenge, signature)
	if err != nil {
		t.Errorf("VerifySignature() failed: %v", err)
	}
}

func TestSignatureIsBase64(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	challenge := "test-base64-encoding"
	signature, err := SignChallenge(privateKey, challenge)
	if err != nil {
		t.Fatalf("SignChallenge() failed: %v", err)
	}

	// Base64文字列であることを確認（デコードできるか）
	if err := VerifySignature(&privateKey.PublicKey, challenge, signature); err != nil {
		t.Errorf("signature is not valid base64: %v", err)
	}
}
