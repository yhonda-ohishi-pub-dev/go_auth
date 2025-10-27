package authclient

import (
	"fmt"

	"github.com/yhonda-ohishi/go_auth/internal/crypto"
	"github.com/yhonda-ohishi/go_auth/pkg/keygen"
)

// LoadPrivateKeyFromFile はファイルから秘密鍵を読み込みます
func LoadPrivateKeyFromFile(filename string) (*Client, error) {
	privateKey, err := keygen.LoadPrivateKey(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	return &Client{
		privateKey: privateKey,
	}, nil
}

// signChallenge はチャレンジに署名します
func (c *Client) signChallenge(challenge string) (string, error) {
	if c.privateKey == nil {
		return "", ErrInvalidPrivateKey
	}

	signature, err := crypto.SignChallenge(c.privateKey, challenge)
	if err != nil {
		return "", fmt.Errorf("failed to sign challenge: %w", err)
	}

	return signature, nil
}
