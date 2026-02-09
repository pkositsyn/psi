package crypto

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
)

type ECDHKey struct {
	privateKey *ecdh.PrivateKey
}

func GenerateECDHKey() (*ECDHKey, error) {
	curve := ecdh.P256()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDHKey{
		privateKey: privateKey,
	}, nil
}

func ECDHApply(key *ECDHKey, data string) (string, error) {
	inputBytes, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", fmt.Errorf("ошибка декодирования base64: %w", err)
	}

	curve := elliptic.P256()
	var x, y *big.Int

	if len(inputBytes) == 32 {
		x, y = curve.ScalarBaseMult(inputBytes)
	} else if len(inputBytes) == 65 && inputBytes[0] == 0x04 {
		x = new(big.Int).SetBytes(inputBytes[1:33])
		y = new(big.Int).SetBytes(inputBytes[33:65])
		
		if !curve.IsOnCurve(x, y) {
			return "", fmt.Errorf("невалидная точка на кривой")
		}
	} else {
		return "", fmt.Errorf("неверный формат данных: ожидается 32 байта (HMAC) или 65 байт (точка на кривой), получено %d", len(inputBytes))
	}

	rx, ry := curve.ScalarMult(x, y, key.privateKey.Bytes())

	return base64.StdEncoding.EncodeToString(elliptic.Marshal(curve, rx, ry)), nil
}

func (k *ECDHKey) Bytes() []byte {
	return k.privateKey.Bytes()
}

func NewECDHKeyFromBytes(keyBytes []byte) (*ECDHKey, error) {
	curve := ecdh.P256()
	privateKey, err := curve.NewPrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ошибка создания ECDH ключа: %w", err)
	}

	return &ECDHKey{
		privateKey: privateKey,
	}, nil
}
