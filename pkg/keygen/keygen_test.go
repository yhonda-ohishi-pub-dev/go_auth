package keygen

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantErr bool
	}{
		{
			name:    "valid 2048 bits",
			bits:    2048,
			wantErr: false,
		},
		{
			name:    "valid 4096 bits",
			bits:    4096,
			wantErr: false,
		},
		{
			name:    "invalid 1024 bits",
			bits:    1024,
			wantErr: true,
		},
		{
			name:    "invalid 512 bits",
			bits:    512,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GeneratePrivateKey(tt.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("GeneratePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && key == nil {
				t.Error("GeneratePrivateKey() returned nil key")
			}
			if !tt.wantErr && key.N.BitLen() != tt.bits {
				t.Errorf("GeneratePrivateKey() key size = %d, want %d", key.N.BitLen(), tt.bits)
			}
		})
	}
}

func TestEncodePrivateKeyToPEM(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	pem, err := EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		t.Errorf("EncodePrivateKeyToPEM() error = %v", err)
		return
	}

	if len(pem) == 0 {
		t.Error("EncodePrivateKeyToPEM() returned empty PEM")
	}

	// PEMヘッダーの確認
	if string(pem[:27]) != "-----BEGIN PRIVATE KEY-----" {
		t.Error("EncodePrivateKeyToPEM() invalid PEM header")
	}
}

func TestEncodePublicKeyToPEM(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	publicKey := &privateKey.PublicKey
	pem, err := EncodePublicKeyToPEM(publicKey)
	if err != nil {
		t.Errorf("EncodePublicKeyToPEM() error = %v", err)
		return
	}

	if len(pem) == 0 {
		t.Error("EncodePublicKeyToPEM() returned empty PEM")
	}

	// PEMヘッダーの確認
	if string(pem[:26]) != "-----BEGIN PUBLIC KEY-----" {
		t.Error("EncodePublicKeyToPEM() invalid PEM header")
	}
}

func TestSaveAndLoadPrivateKey(t *testing.T) {
	// 一時ディレクトリを作成
	tmpDir := t.TempDir()
	privateKeyFile := filepath.Join(tmpDir, "private.pem")

	// 秘密鍵を生成
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// 保存
	if err := SavePrivateKey(privateKeyFile, privateKey); err != nil {
		t.Errorf("SavePrivateKey() error = %v", err)
		return
	}

	// ファイルが存在するか確認
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		t.Error("SavePrivateKey() file not created")
		return
	}

	// 読み込み
	loadedKey, err := LoadPrivateKey(privateKeyFile)
	if err != nil {
		t.Errorf("LoadPrivateKey() error = %v", err)
		return
	}

	// 鍵が一致するか確認
	if privateKey.N.Cmp(loadedKey.N) != 0 {
		t.Error("LoadPrivateKey() loaded key does not match original")
	}
}

func TestSaveAndLoadPublicKey(t *testing.T) {
	// 一時ディレクトリを作成
	tmpDir := t.TempDir()
	publicKeyFile := filepath.Join(tmpDir, "public.pem")

	// 鍵ペアを生成
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// 保存
	if err := SavePublicKey(publicKeyFile, publicKey); err != nil {
		t.Errorf("SavePublicKey() error = %v", err)
		return
	}

	// ファイルが存在するか確認
	if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
		t.Error("SavePublicKey() file not created")
		return
	}

	// 読み込み
	loadedKey, err := LoadPublicKey(publicKeyFile)
	if err != nil {
		t.Errorf("LoadPublicKey() error = %v", err)
		return
	}

	// 鍵が一致するか確認
	if publicKey.N.Cmp(loadedKey.N) != 0 || publicKey.E != loadedKey.E {
		t.Error("LoadPublicKey() loaded key does not match original")
	}
}

func TestGenerateAndSaveKeyPair(t *testing.T) {
	// 一時ディレクトリを作成
	tmpDir := t.TempDir()
	privateKeyFile := filepath.Join(tmpDir, "private.pem")
	publicKeyFile := filepath.Join(tmpDir, "public.pem")

	// 鍵ペアを生成して保存
	if err := GenerateAndSaveKeyPair(privateKeyFile, publicKeyFile, 2048); err != nil {
		t.Errorf("GenerateAndSaveKeyPair() error = %v", err)
		return
	}

	// 両方のファイルが存在するか確認
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		t.Error("GenerateAndSaveKeyPair() private key file not created")
	}
	if _, err := os.Stat(publicKeyFile); os.IsNotExist(err) {
		t.Error("GenerateAndSaveKeyPair() public key file not created")
	}

	// 読み込んで検証
	privateKey, err := LoadPrivateKey(privateKeyFile)
	if err != nil {
		t.Errorf("failed to load private key: %v", err)
		return
	}

	publicKey, err := LoadPublicKey(publicKeyFile)
	if err != nil {
		t.Errorf("failed to load public key: %v", err)
		return
	}

	// 鍵ペアが対応しているか確認
	if privateKey.PublicKey.N.Cmp(publicKey.N) != 0 {
		t.Error("key pair mismatch")
	}
}

func TestParsePrivateKeyPEM(t *testing.T) {
	// 秘密鍵を生成
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	// PEM形式にエンコード
	pemData, err := EncodePrivateKeyToPEM(privateKey)
	if err != nil {
		t.Fatalf("failed to encode private key: %v", err)
	}

	// パース
	parsedKey, err := ParsePrivateKeyPEM(pemData)
	if err != nil {
		t.Errorf("ParsePrivateKeyPEM() error = %v", err)
		return
	}

	// 鍵が一致するか確認
	if privateKey.N.Cmp(parsedKey.N) != 0 {
		t.Error("ParsePrivateKeyPEM() parsed key does not match original")
	}
}

func TestParsePublicKeyPEM(t *testing.T) {
	// 鍵ペアを生成
	privateKey, err := GeneratePrivateKey(2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}
	publicKey := &privateKey.PublicKey

	// PEM形式にエンコード
	pemData, err := EncodePublicKeyToPEM(publicKey)
	if err != nil {
		t.Fatalf("failed to encode public key: %v", err)
	}

	// パース
	parsedKey, err := ParsePublicKeyPEM(pemData)
	if err != nil {
		t.Errorf("ParsePublicKeyPEM() error = %v", err)
		return
	}

	// 鍵が一致するか確認
	if publicKey.N.Cmp(parsedKey.N) != 0 || publicKey.E != parsedKey.E {
		t.Error("ParsePublicKeyPEM() parsed key does not match original")
	}
}
