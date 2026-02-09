package tests

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/pkositsyn/psi/internal/commands"
	"github.com/pkositsyn/psi/internal/crypto"
	psio "github.com/pkositsyn/psi/internal/io"
)

type memReadCloser struct {
	*bytes.Reader
}

func (m *memReadCloser) Close() error {
	return nil
}

func newMemReadCloser(data string) io.ReadCloser {
	return &memReadCloser{bytes.NewReader([]byte(data))}
}

type memWriteCloser struct {
	*bytes.Buffer
}

func (m *memWriteCloser) Close() error {
	return nil
}

func newMemWriteCloser() *memWriteCloser {
	return &memWriteCloser{&bytes.Buffer{}}
}

func TestPSIBasicIntersection(t *testing.T) {
	partnerData, err := os.ReadFile("testdata/partner_basic.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать partner_basic.tsv: %v", err)
	}

	passportData, err := os.ReadFile("testdata/passport_basic.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать passport_basic.tsv: %v", err)
	}

	result := runPSIProtocol(t, string(partnerData), string(passportData))

	expectedMappings := map[string]string{
		"puid_123": "user_001",
		"puid_456": "user_004",
		"puid_789": "user_003",
		"puid_999": "",
	}

	validateResult(t, result, expectedMappings)
}

func TestPSINoIntersection(t *testing.T) {
	partnerData, err := os.ReadFile("testdata/partner_no_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать partner_no_intersection.tsv: %v", err)
	}

	passportData, err := os.ReadFile("testdata/passport_no_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать passport_no_intersection.tsv: %v", err)
	}

	result := runPSIProtocol(t, string(partnerData), string(passportData))

	expectedMappings := map[string]string{
		"puid_123": "",
		"puid_456": "",
	}

	validateResult(t, result, expectedMappings)
}

func TestPSIFullIntersection(t *testing.T) {
	partnerData, err := os.ReadFile("testdata/partner_full_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать partner_full_intersection.tsv: %v", err)
	}

	passportData, err := os.ReadFile("testdata/passport_full_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать passport_full_intersection.tsv: %v", err)
	}

	result := runPSIProtocol(t, string(partnerData), string(passportData))

	expectedMappings := map[string]string{
		"puid_123": "user_001",
		"puid_456": "user_002",
	}

	validateResult(t, result, expectedMappings)
}

func runPSIProtocol(t *testing.T, partnerInput, passportInput string) string {
	keyK, err := crypto.GenerateHMACKey()
	if err != nil {
		t.Fatalf("ошибка генерации HMAC ключа: %v", err)
	}

	keyP, err := crypto.GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ECDH ключа P: %v", err)
	}

	partnerStep1Output := partnerStep1(keyK, keyP, partnerInput)

	keyY, err := crypto.GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ECDH ключа Y: %v", err)
	}

	partnerEncryptedY, passportEncrypted := passportStep1(keyK, keyY, partnerStep1Output, passportInput)

	partnerFinal := partnerStep2(keyP, partnerInput, passportEncrypted, partnerEncryptedY)

	passportFinal := passportStep2Helper(passportEncrypted, partnerFinal)

	return passportFinal
}

func passportStep2Helper(passportEncrypted, partnerFinal string) string {
	readerPartner := psio.NewTSVReader(newMemReadCloser(partnerFinal))
	defer readerPartner.Close()
	partnerData, _ := commands.LoadPartnerFinalData(readerPartner)

	readerPassport := psio.NewTSVReader(newMemReadCloser(passportEncrypted))
	defer readerPassport.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessPassportStep2(readerPassport, writer, partnerData)

	writer.Close()
	return output.String()
}

func TestPSIInvalidPhoneFormat(t *testing.T) {
	invalidPartnerData := "79991234567\tuser_001\n+79991234568\tuser_002\n"

	keyK, _ := crypto.GenerateHMACKey()
	keyP, _ := crypto.GenerateECDHKey()

	reader := psio.NewTSVReader(newMemReadCloser(invalidPartnerData))
	defer reader.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	_, err := commands.ProcessPartnerStep1(reader, writer, keyK, keyP)
	if err == nil {
		t.Fatal("ожидалась ошибка валидации телефона, но её не было")
	}
	if err.Error() == "" {
		t.Fatal("ошибка валидации не содержит сообщения")
	}
}

func validateResult(t *testing.T, result string, expected map[string]string) {
	reader := psio.NewTSVReader(newMemReadCloser(result))
	defer reader.Close()

	actual := make(map[string]string)
	for {
		record, err := reader.Read()
		if err == psio.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ошибка чтения результата: %v", err)
		}

		if len(record) != 2 {
			t.Fatalf("неверный формат результата")
		}

		puid := record[0]
		userID := record[1]
		actual[puid] = userID
	}

	if len(actual) != len(expected) {
		t.Errorf("неверное количество записей: ожидается %d, получено %d", len(expected), len(actual))
	}

	for puid, expectedUserID := range expected {
		actualUserID, found := actual[puid]
		if !found {
			t.Errorf("puid %s не найден в результате", puid)
			continue
		}

		if actualUserID != expectedUserID {
			t.Errorf("для puid %s ожидается user_id %q, получено %q", puid, expectedUserID, actualUserID)
		}
	}
}
