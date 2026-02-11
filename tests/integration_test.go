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

func (m *memReadCloser) Reset() {
	m.Seek(0, io.SeekStart)
}

func (m *memReadCloser) Close() error {
	return nil
}

func newMemReadCloser(data string) psio.ReadResetCloser {
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
	bobData, err := os.ReadFile("testdata/bob_basic.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать bob_basic.tsv: %v", err)
	}

	aliceData, err := os.ReadFile("testdata/alice_basic.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать alice_basic.tsv: %v", err)
	}

	result := runPSIProtocol(t, string(bobData), string(aliceData))

	expectedMappings := map[string]string{
		"a_user_id_123": "b_user_001",
		"a_user_id_456": "b_user_004",
		"a_user_id_789": "b_user_003",
		"a_user_id_999": "",
	}

	validateResult(t, result, expectedMappings)
}

func TestPSINoIntersection(t *testing.T) {
	bobData, err := os.ReadFile("testdata/bob_no_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать bob_no_intersection.tsv: %v", err)
	}

	aliceData, err := os.ReadFile("testdata/alice_no_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать alice_no_intersection.tsv: %v", err)
	}

	result := runPSIProtocol(t, string(bobData), string(aliceData))

	expectedMappings := map[string]string{
		"a_user_id_123": "",
		"a_user_id_456": "",
	}

	validateResult(t, result, expectedMappings)
}

func TestPSIFullIntersection(t *testing.T) {
	bobData, err := os.ReadFile("testdata/bob_full_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать bob_full_intersection.tsv: %v", err)
	}

	aliceData, err := os.ReadFile("testdata/alice_full_intersection.tsv")
	if err != nil {
		t.Fatalf("не удалось прочитать alice_full_intersection.tsv: %v", err)
	}

	result := runPSIProtocol(t, string(bobData), string(aliceData))

	expectedMappings := map[string]string{
		"a_user_id_123": "b_user_001",
		"a_user_id_456": "b_user_002",
	}

	validateResult(t, result, expectedMappings)
}

func runPSIProtocol(t *testing.T, bobInput, aliceInput string) string {
	keyK, err := crypto.GenerateHMACKey()
	if err != nil {
		t.Fatalf("ошибка генерации HMAC ключа: %v", err)
	}

	keyB, err := crypto.GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ECDH ключа B: %v", err)
	}

	bobStep1Output := bobStep1(keyK, keyB, bobInput)

	keyA, err := crypto.GenerateECDHKey()
	if err != nil {
		t.Fatalf("ошибка генерации ECDH ключа A: %v", err)
	}

	bobEncryptedA, aliceEncrypted := aliceStep1(keyK, keyA, bobStep1Output, aliceInput)

	bobFinal := bobStep2(keyB, bobInput, aliceEncrypted, bobEncryptedA)

	aliceFinal := aliceStep2Helper(aliceEncrypted, bobFinal)

	return aliceFinal
}

func bobStep1(keyK []byte, keyB *crypto.ECDHKey, input string) string {
	reader := psio.NewTSVReader(newMemReadCloser(input))
	defer reader.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessBobStep1(reader, writer, keyK, keyB, 128)

	writer.Close()
	return output.String()
}

func aliceStep1(keyK []byte, keyA *crypto.ECDHKey, bobEncrypted, aliceInput string) (string, string) {
	readerBob := psio.NewTSVReader(newMemReadCloser(bobEncrypted))
	defer readerBob.Close()

	outputBob := newMemWriteCloser()
	writerBob := psio.NewTSVWriter(outputBob)
	defer writerBob.Close()

	commands.ProcessBobDataStep1(readerBob, writerBob, keyA, 128)
	writerBob.Close()

	readerAlice := psio.NewTSVReader(newMemReadCloser(aliceInput))
	defer readerAlice.Close()

	outputAlice := newMemWriteCloser()
	writerAlice := psio.NewTSVWriter(outputAlice)
	defer writerAlice.Close()

	commands.ProcessAliceDataStep1(readerAlice, writerAlice, keyK, keyA, 128)
	writerAlice.Close()

	return outputBob.String(), outputAlice.String()
}

func bobStep2(keyB *crypto.ECDHKey, originalInput, aliceEncrypted, bobEncryptedA string) string {
	readerBobEnc := psio.NewTSVReader(newMemReadCloser(bobEncryptedA))
	defer readerBobEnc.Close()
	bobEncMap, _ := commands.LoadIndexedData(readerBobEnc)

	readerOriginal := psio.NewTSVReader(newMemReadCloser(originalInput))
	defer readerOriginal.Close()
	originalData, _ := commands.LoadOriginalData(readerOriginal)

	readerAlice := psio.NewTSVReader(newMemReadCloser(aliceEncrypted))
	defer readerAlice.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessBobStep2(readerAlice, writer, keyB, bobEncMap, originalData, 128)

	writer.Close()
	return output.String()
}

func aliceStep2Helper(aliceEncrypted, bobFinal string) string {
	readerBob := psio.NewTSVReader(newMemReadCloser(bobFinal))
	defer readerBob.Close()
	bobData, _ := commands.LoadBobFinalData(readerBob)

	readerAlice := psio.NewTSVReader(newMemReadCloser(aliceEncrypted))
	defer readerAlice.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessAliceStep2(readerAlice, writer, bobData)

	writer.Close()
	return output.String()
}

func TestPSIInvalidPhoneFormat(t *testing.T) {
	invalidPartnerData := "79991234567\tb_user_001\n+79991234568\tb_user_002\n"

	keyK, _ := crypto.GenerateHMACKey()
	keyB, _ := crypto.GenerateECDHKey()

	reader := psio.NewTSVReader(newMemReadCloser(invalidPartnerData))
	defer reader.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	_, err := commands.ProcessBobStep1(reader, writer, keyK, keyB, 512)
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

		aUserID := record[0]
		bUserID := record[1]
		actual[aUserID] = bUserID
	}

	if len(actual) != len(expected) {
		t.Errorf("неверное количество записей: ожидается %d, получено %d", len(expected), len(actual))
	}

	for aUserID, expectedUserID := range expected {
		actualUserID, found := actual[aUserID]
		if !found {
			t.Errorf("a_user_id %s не найден в результате", aUserID)
			continue
		}

		if actualUserID != expectedUserID {
			t.Errorf("для a_user_id %s ожидается b_user_id %q, получено %q", aUserID, expectedUserID, actualUserID)
		}
	}
}
