package crypto

import (
	"encoding/base64"
	"testing"
)

func TestGenerateECDHKey(t *testing.T) {
	key, err := GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ECDH ключа: %v", err)
	}

	if key == nil {
		t.Fatal("ключ не должен быть nil")
	}

	if len(key.Bytes()) == 0 {
		t.Error("ключ не должен быть пустым")
	}
}

func TestECDHApply(t *testing.T) {
	// Генерируем ключи
	keyP, err := GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ключа P: %v", err)
	}

	keyY, err := GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ключа Y: %v", err)
	}

	// Создаем тестовые данные (HMAC хеш телефона)
	hmacKey := []byte("test-hmac-key-32-bytes-padding!!")
	phone := "+79001234567"
	hashed := HMAC(hmacKey, []byte(phone))

	// Применяем ключ P: H(phone)^P
	encP, err := ECDHApply(keyP, hashed)
	if err != nil {
		t.Fatalf("ошибка применения ключа P: %v", err)
	}

	// Проверяем валидность base64
	_, err = base64.StdEncoding.DecodeString(encP)
	if err != nil {
		t.Errorf("результат не является валидным base64: %v", err)
	}

	// Применяем ключ Y: H(phone)^P^Y
	encPY, err := ECDHApply(keyY, encP)
	if err != nil {
		t.Fatalf("ошибка применения ключа Y: %v", err)
	}

	// Проверяем детерминированность
	encP2, err := ECDHApply(keyP, hashed)
	if err != nil {
		t.Fatalf("ошибка повторного применения ключа P: %v", err)
	}

	if encP != encP2 {
		t.Error("ECDH операция должна быть детерминированной")
	}

	// Проверяем что результат отличается от исходных данных
	if encP == hashed {
		t.Error("зашифрованные данные не должны совпадать с исходными")
	}

	if encPY == encP {
		t.Error("двойное шифрование должно давать другой результат")
	}
}

func TestECDHCommutativity(t *testing.T) {
	// Тест коммутативности: (H^P)^Y должно быть равно (H^Y)^P
	keyP, _ := GenerateECDHKey()
	keyY, _ := GenerateECDHKey()

	hmacKey := []byte("test-hmac-key-32-bytes-padding!!")
	phone := "+79001234567"
	hashed := HMAC(hmacKey, []byte(phone))

	// Путь 1: H -> H^P -> H^P^Y
	encP, err := ECDHApply(keyP, hashed)
	if err != nil {
		t.Fatalf("ошибка применения P: %v", err)
	}

	encPY, err := ECDHApply(keyY, encP)
	if err != nil {
		t.Fatalf("ошибка применения Y после P: %v", err)
	}

	// Путь 2: H -> H^Y -> H^Y^P
	encY, err := ECDHApply(keyY, hashed)
	if err != nil {
		t.Fatalf("ошибка применения Y: %v", err)
	}

	encYP, err := ECDHApply(keyP, encY)
	if err != nil {
		t.Fatalf("ошибка применения P после Y: %v", err)
	}

	// Проверяем коммутативность
	if encPY != encYP {
		t.Error("операция должна быть коммутативной: H^P^Y должно быть равно H^Y^P")
	}
}
