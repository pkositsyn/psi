package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGenerateHMACKey(t *testing.T) {
	key, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("ошибка генерации ключа: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("ожидается ключ длины 32 байта, получено %d", len(key))
	}

	// Проверяем что ключи уникальные
	key2, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("ошибка генерации второго ключа: %v", err)
	}

	if string(key) == string(key2) {
		t.Error("два ключа не должны совпадать")
	}
}

func TestHMAC(t *testing.T) {
	key := []byte("test-key-32-bytes-long-padding!!")
	data := []byte("+79001234567")

	hash := HMAC(nil, key, data)

	// Проверяем что результат это валидный base64
	_, err := base64.StdEncoding.DecodeString(hash)
	if err != nil {
		t.Errorf("результат HMAC не является валидным base64: %v", err)
	}

	// Проверяем детерминированность
	hash2 := HMAC(nil, key, data)
	if hash != hash2 {
		t.Error("HMAC должен быть детерминированным")
	}

	// Проверяем что разные данные дают разные хеши
	hash3 := HMAC(nil, key, []byte("+79001234568"))
	if hash == hash3 {
		t.Error("разные данные должны давать разные хеши")
	}
}
