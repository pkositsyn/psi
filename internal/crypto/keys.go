package crypto

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func SaveHMACKey(filename string, hmacKey []byte) error {
	encoded := hex.EncodeToString(hmacKey)
	return os.WriteFile(filename, []byte(encoded), 0600)
}

func LoadHMACKey(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	encoded := strings.TrimSpace(string(data))
	hmacKey, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования HMAC ключа: %w", err)
	}

	return hmacKey, nil
}

func SaveECDHKey(filename string, ecdhKey *ECDHKey) error {
	encoded := hex.EncodeToString(ecdhKey.Bytes())
	return os.WriteFile(filename, []byte(encoded), 0600)
}

func LoadECDHKey(filename string) (*ECDHKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	encoded := strings.TrimSpace(string(data))
	keyBytes, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("ошибка декодирования ECDH ключа: %w", err)
	}

	return NewECDHKeyFromBytes(keyBytes)
}
