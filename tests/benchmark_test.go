package tests

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/pkositsyn/psi/internal/commands"
	"github.com/pkositsyn/psi/internal/crypto"
	psio "github.com/pkositsyn/psi/internal/io"
)

func generateRandomPhone() string {
	return fmt.Sprintf("+7999%07d", rand.Intn(10000000))
}

func generatePartnerData(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += fmt.Sprintf("%s\tuser_%06d\n", generateRandomPhone(), i)
	}
	return result
}

func generatePassportData(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += fmt.Sprintf("puid_%06d\t%s\n", i, generateRandomPhone())
	}
	return result
}

func BenchmarkPartnerStep1_100(b *testing.B) {
	benchmarkPartnerStep1(b, 100)
}

func BenchmarkPartnerStep1_1000(b *testing.B) {
	benchmarkPartnerStep1(b, 1000)
}

func BenchmarkPartnerStep1_10000(b *testing.B) {
	benchmarkPartnerStep1(b, 10000)
}

func benchmarkPartnerStep1(b *testing.B, n int) {
	input := generatePartnerData(n)
	keyK, _ := crypto.GenerateHMACKey()
	keyP, _ := crypto.GenerateECDHKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := psio.NewTSVReader(newMemReadCloser(input))
		output := newMemWriteCloser()
		writer := psio.NewTSVWriter(output)

		commands.ProcessPartnerStep1(reader, writer, keyK, keyP)

		writer.Close()
		reader.Close()
	}
}

func BenchmarkPassportStep1Partner_100(b *testing.B) {
	benchmarkPassportStep1Partner(b, 100)
}

func BenchmarkPassportStep1Partner_1000(b *testing.B) {
	benchmarkPassportStep1Partner(b, 1000)
}

func BenchmarkPassportStep1Partner_10000(b *testing.B) {
	benchmarkPassportStep1Partner(b, 10000)
}

func benchmarkPassportStep1Partner(b *testing.B, n int) {
	partnerInput := generatePartnerData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyP, _ := crypto.GenerateECDHKey()
	keyY, _ := crypto.GenerateECDHKey()

	partnerEncrypted := partnerStep1(keyK, keyP, partnerInput)

	b.ResetTimer()
	for b.Loop() {
		readerPartner := psio.NewTSVReader(newMemReadCloser(partnerEncrypted))
		outputPartner := newMemWriteCloser()
		writerPartner := psio.NewTSVWriter(outputPartner)

		commands.ProcessPartnerDataStep1(readerPartner, writerPartner, keyY)

		writerPartner.Close()
		readerPartner.Close()
	}
}

func BenchmarkPassportStep1Passport_100(b *testing.B) {
	benchmarkPassportStep1Passport(b, 100)
}

func BenchmarkPassportStep1Passport_1000(b *testing.B) {
	benchmarkPassportStep1Passport(b, 1000)
}

func BenchmarkPassportStep1Passport_10000(b *testing.B) {
	benchmarkPassportStep1Passport(b, 10000)
}

func benchmarkPassportStep1Passport(b *testing.B, n int) {
	passportInput := generatePassportData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyY, _ := crypto.GenerateECDHKey()

	b.ResetTimer()
	for b.Loop() {
		readerPassport := psio.NewTSVReader(newMemReadCloser(passportInput))
		outputPassport := newMemWriteCloser()
		writerPassport := psio.NewTSVWriter(outputPassport)

		commands.ProcessPassportDataStep1(readerPassport, writerPassport, keyK, keyY)

		writerPassport.Close()
		readerPassport.Close()
	}
}

func BenchmarkPartnerStep2_100(b *testing.B) {
	benchmarkPartnerStep2(b, 100)
}

func BenchmarkPartnerStep2_1000(b *testing.B) {
	benchmarkPartnerStep2(b, 1000)
}

func BenchmarkPartnerStep2_10000(b *testing.B) {
	benchmarkPartnerStep2(b, 10000)
}

func benchmarkPartnerStep2(b *testing.B, n int) {
	partnerInput := generatePartnerData(n)
	passportInput := generatePassportData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyP, _ := crypto.GenerateECDHKey()
	keyY, _ := crypto.GenerateECDHKey()

	partnerStep1Output := partnerStep1(keyK, keyP, partnerInput)
	partnerEncryptedY, passportEncrypted := passportStep1(keyK, keyY, partnerStep1Output, passportInput)

	b.ResetTimer()
	for b.Loop() {
		readerPartnerEnc := psio.NewTSVReader(newMemReadCloser(partnerEncryptedY))
		partnerEncMap, _ := commands.LoadIndexedData(readerPartnerEnc)
		readerPartnerEnc.Close()

		readerOriginal := psio.NewTSVReader(newMemReadCloser(partnerInput))
		originalData, _ := commands.LoadOriginalData(readerOriginal)
		readerOriginal.Close()

		readerPassport := psio.NewTSVReader(newMemReadCloser(passportEncrypted))
		output := newMemWriteCloser()
		writer := psio.NewTSVWriter(output)

		commands.ProcessPartnerStep2(readerPassport, writer, keyP, partnerEncMap, originalData)

		writer.Close()
		readerPassport.Close()
	}
}

func BenchmarkPassportStep2_100(b *testing.B) {
	benchmarkPassportStep2(b, 100)
}

func BenchmarkPassportStep2_1000(b *testing.B) {
	benchmarkPassportStep2(b, 1000)
}

func BenchmarkPassportStep2_10000(b *testing.B) {
	benchmarkPassportStep2(b, 10000)
}

func benchmarkPassportStep2(b *testing.B, n int) {
	partnerInput := generatePartnerData(n)
	passportInput := generatePassportData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyP, _ := crypto.GenerateECDHKey()
	keyY, _ := crypto.GenerateECDHKey()

	partnerStep1Output := partnerStep1(keyK, keyP, partnerInput)
	partnerEncryptedY, passportEncrypted := passportStep1(keyK, keyY, partnerStep1Output, passportInput)
	partnerFinal := partnerStep2(keyP, partnerInput, passportEncrypted, partnerEncryptedY)

	b.ResetTimer()
	for b.Loop() {
		readerPartner := psio.NewTSVReader(newMemReadCloser(partnerFinal))
		partnerData, _ := commands.LoadPartnerFinalData(readerPartner)
		readerPartner.Close()

		readerPassport := psio.NewTSVReader(newMemReadCloser(passportEncrypted))
		output := newMemWriteCloser()
		writer := psio.NewTSVWriter(output)

		commands.ProcessPassportStep2(readerPassport, writer, partnerData)

		writer.Close()
		readerPassport.Close()
	}
}

func partnerStep1(keyK []byte, keyP *crypto.ECDHKey, input string) string {
	reader := psio.NewTSVReader(newMemReadCloser(input))
	defer reader.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessPartnerStep1(reader, writer, keyK, keyP)

	writer.Close()
	return output.String()
}

func passportStep1(keyK []byte, keyY *crypto.ECDHKey, partnerEncrypted, passportInput string) (string, string) {
	readerPartner := psio.NewTSVReader(newMemReadCloser(partnerEncrypted))
	defer readerPartner.Close()

	outputPartner := newMemWriteCloser()
	writerPartner := psio.NewTSVWriter(outputPartner)
	defer writerPartner.Close()

	commands.ProcessPartnerDataStep1(readerPartner, writerPartner, keyY)
	writerPartner.Close()

	readerPassport := psio.NewTSVReader(newMemReadCloser(passportInput))
	defer readerPassport.Close()

	outputPassport := newMemWriteCloser()
	writerPassport := psio.NewTSVWriter(outputPassport)
	defer writerPassport.Close()

	commands.ProcessPassportDataStep1(readerPassport, writerPassport, keyK, keyY)
	writerPassport.Close()

	return outputPartner.String(), outputPassport.String()
}

func partnerStep2(keyP *crypto.ECDHKey, originalInput, passportEncrypted, partnerEncryptedY string) string {
	readerPartnerEnc := psio.NewTSVReader(newMemReadCloser(partnerEncryptedY))
	defer readerPartnerEnc.Close()
	partnerEncMap, _ := commands.LoadIndexedData(readerPartnerEnc)

	readerOriginal := psio.NewTSVReader(newMemReadCloser(originalInput))
	defer readerOriginal.Close()
	originalData, _ := commands.LoadOriginalData(readerOriginal)

	readerPassport := psio.NewTSVReader(newMemReadCloser(passportEncrypted))
	defer readerPassport.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessPartnerStep2(readerPassport, writer, keyP, partnerEncMap, originalData)

	writer.Close()
	return output.String()
}
