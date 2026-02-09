package validation

import (
	"fmt"
	"regexp"
)

var e164Regex = regexp.MustCompile(`^\+[1-9]\d{6,14}$`)

func ValidateE164Phone(phone string) error {
	if !e164Regex.MatchString(phone) {
		return fmt.Errorf("телефон '%s' не соответствует стандарту E.164 (ожидается формат +[код страны][номер], всего 7-15 цифр)", phone)
	}
	return nil
}
