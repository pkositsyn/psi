package validation

import (
	"testing"
)

func TestValidateE164Phone(t *testing.T) {
	validPhones := []string{
		"+79991234567",
		"+12025551234",
		"+441234567890",
		"+861234567890",
		"+7123456789",
		"+123456789012345",
	}

	for _, phone := range validPhones {
		if err := ValidateE164Phone(phone); err != nil {
			t.Errorf("телефон %s должен быть валидным, но получена ошибка: %v", phone, err)
		}
	}

	invalidPhones := []string{
		"79991234567",
		"+0123456789",
		"+1",
		"+12345",
		"12345678901234",
		"+1234567890123456",
		"+1-234-567-8901",
		"+1 234 567 8901",
		"+1(234)5678901",
		"",
		"phone",
		"+abc1234567",
	}

	for _, phone := range invalidPhones {
		if err := ValidateE164Phone(phone); err == nil {
			t.Errorf("телефон %s должен быть невалидным, но ошибки не получено", phone)
		}
	}
}
