package crypto

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

func SaveHMACKey(filename string, hmacKey []byte) error {
	encoded := base64.StdEncoding.EncodeToString(hmacKey)
	return os.WriteFile(filename, []byte(encoded), 0600)
}

func LoadHMACKey(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	encoded := strings.TrimSpace(string(data))
	hmacKey, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования HMAC ключа: %w", err)
	}

	return hmacKey, nil
}

func SaveECDHKey(filename string, ecdhKey *ECDHKey) error {
	encoded := base64.StdEncoding.EncodeToString(ecdhKey.Bytes())
	return os.WriteFile(filename, []byte(encoded), 0600)
}

func LoadECDHKey(filename string) (*ECDHKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	encoded := strings.TrimSpace(string(data))
	keyBytes, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования ECDH ключа: %w", err)
	}

	return NewECDHKeyFromBytes(keyBytes)
}
