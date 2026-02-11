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

func generateBobData(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += fmt.Sprintf("%s\tuser_%06d\n", generateRandomPhone(), i)
	}
	return result
}

func generateAliceData(n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += fmt.Sprintf("puid_%06d\t%s\n", i, generateRandomPhone())
	}
	return result
}

func BenchmarkBobStep1_100(b *testing.B) {
	benchmarkBobStep1(b, 100)
}

func BenchmarkBobStep1_1000(b *testing.B) {
	benchmarkBobStep1(b, 1000)
}

func BenchmarkBobStep1_10000(b *testing.B) {
	benchmarkBobStep1(b, 10000)
}

func BenchmarkBobStep1_100000(b *testing.B) {
	benchmarkBobStep1(b, 100000)
}

func benchmarkBobStep1(b *testing.B, n int) {
	input := generateBobData(n)
	keyK, _ := crypto.GenerateHMACKey()
	keyB, _ := crypto.GenerateECDHKey()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := psio.NewTSVReader(newMemReadCloser(input))
		output := newMemWriteCloser()
		writer := psio.NewTSVWriter(output)

		commands.ProcessBobStep1(reader, writer, keyK, keyB, 128)

		writer.Close()
		reader.Close()
	}
}

func BenchmarkAliceStep1Bob_100(b *testing.B) {
	benchmarkAliceStep1Bob(b, 100)
}

func BenchmarkAliceStep1Bob_1000(b *testing.B) {
	benchmarkAliceStep1Bob(b, 1000)
}

func BenchmarkAliceStep1Bob_10000(b *testing.B) {
	benchmarkAliceStep1Bob(b, 10000)
}

func benchmarkAliceStep1Bob(b *testing.B, n int) {
	bobInput := generateBobData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyB, _ := crypto.GenerateECDHKey()
	keyA, _ := crypto.GenerateECDHKey()

	bobEncrypted := partnerStep1(keyK, keyB, bobInput)

	b.ResetTimer()
	for b.Loop() {
		readerPartner := psio.NewTSVReader(newMemReadCloser(bobEncrypted))
		outputPartner := newMemWriteCloser()
		writerPartner := psio.NewTSVWriter(outputPartner)

		commands.ProcessBobDataStep1(readerPartner, writerPartner, keyA, 128)

		writerPartner.Close()
		readerPartner.Close()
	}
}

func BenchmarkAliceStep1Alice_100(b *testing.B) {
	benchmarkAliceStep1Alice(b, 100)
}

func BenchmarkAliceStep1Alice_1000(b *testing.B) {
	benchmarkAliceStep1Alice(b, 1000)
}

func BenchmarkAliceStep1Alice_10000(b *testing.B) {
	benchmarkAliceStep1Alice(b, 10000)
}

func benchmarkAliceStep1Alice(b *testing.B, n int) {
	aliceInput := generateAliceData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyA, _ := crypto.GenerateECDHKey()

	b.ResetTimer()
	for b.Loop() {
		readerPassport := psio.NewTSVReader(newMemReadCloser(aliceInput))
		outputPassport := newMemWriteCloser()
		writerPassport := psio.NewTSVWriter(outputPassport)

		commands.ProcessAliceDataStep1(readerPassport, writerPassport, keyK, keyA, 128)

		writerPassport.Close()
		readerPassport.Close()
	}
}

func BenchmarkBobStep2_100(b *testing.B) {
	benchmarkBobStep2(b, 100)
}

func BenchmarkBobStep2_1000(b *testing.B) {
	benchmarkBobStep2(b, 1000)
}

func BenchmarkBobStep2_10000(b *testing.B) {
	benchmarkBobStep2(b, 10000)
}

func BenchmarkBobStep2_100000(b *testing.B) {
	benchmarkBobStep2(b, 100000)
}

func benchmarkBobStep2(b *testing.B, n int) {
	bobInput := generateBobData(n)
	aliceInput := generateAliceData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyB, _ := crypto.GenerateECDHKey()
	keyA, _ := crypto.GenerateECDHKey()

	partnerStep1Output := partnerStep1(keyK, keyB, bobInput)
	bobEncryptedY, aliceEncrypted := passportStep1(keyK, keyA, partnerStep1Output, aliceInput)

	b.ResetTimer()
	for b.Loop() {
		readerPartnerEnc := psio.NewTSVReader(newMemReadCloser(bobEncryptedY))
		bobEncMap, _ := commands.LoadIndexedData(readerPartnerEnc)
		readerPartnerEnc.Close()

		readerOriginal := psio.NewTSVReader(newMemReadCloser(bobInput))
		originalData, _ := commands.LoadOriginalData(readerOriginal)
		readerOriginal.Close()

		readerPassport := psio.NewTSVReader(newMemReadCloser(aliceEncrypted))
		output := newMemWriteCloser()
		writer := psio.NewTSVWriter(output)

		commands.ProcessBobStep2(readerPassport, writer, keyB, bobEncMap, originalData, 128)

		writer.Close()
		readerPassport.Close()
	}
}

func BenchmarkAliceStep2_100(b *testing.B) {
	benchmarkAliceStep2(b, 100)
}

func BenchmarkAliceStep2_1000(b *testing.B) {
	benchmarkAliceStep2(b, 1000)
}

func BenchmarkAliceStep2_10000(b *testing.B) {
	benchmarkAliceStep2(b, 10000)
}

func benchmarkAliceStep2(b *testing.B, n int) {
	bobInput := generateBobData(n)
	aliceInput := generateAliceData(n)

	keyK, _ := crypto.GenerateHMACKey()
	keyB, _ := crypto.GenerateECDHKey()
	keyA, _ := crypto.GenerateECDHKey()

	partnerStep1Output := partnerStep1(keyK, keyB, bobInput)
	bobEncryptedY, aliceEncrypted := passportStep1(keyK, keyA, partnerStep1Output, aliceInput)
	bobFinal := partnerStep2(keyB, bobInput, aliceEncrypted, bobEncryptedY)

	b.ResetTimer()
	for b.Loop() {
		readerPartner := psio.NewTSVReader(newMemReadCloser(bobFinal))
		partnerData, _ := commands.LoadBobFinalData(readerPartner)
		readerPartner.Close()

		readerPassport := psio.NewTSVReader(newMemReadCloser(aliceEncrypted))
		output := newMemWriteCloser()
		writer := psio.NewTSVWriter(output)

		commands.ProcessAliceStep2(readerPassport, writer, partnerData)

		writer.Close()
		readerPassport.Close()
	}
}

func partnerStep1(keyK []byte, keyB *crypto.ECDHKey, input string) string {
	reader := psio.NewTSVReader(newMemReadCloser(input))
	defer reader.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessBobStep1(reader, writer, keyK, keyB, 512)

	writer.Close()
	return output.String()
}

func passportStep1(keyK []byte, keyA *crypto.ECDHKey, bobEncrypted, aliceInput string) (string, string) {
	readerPartner := psio.NewTSVReader(newMemReadCloser(bobEncrypted))
	defer readerPartner.Close()

	outputPartner := newMemWriteCloser()
	writerPartner := psio.NewTSVWriter(outputPartner)
	defer writerPartner.Close()

	commands.ProcessBobDataStep1(readerPartner, writerPartner, keyA, 128)
	writerPartner.Close()

	readerPassport := psio.NewTSVReader(newMemReadCloser(aliceInput))
	defer readerPassport.Close()

	outputPassport := newMemWriteCloser()
	writerPassport := psio.NewTSVWriter(outputPassport)
	defer writerPassport.Close()

	commands.ProcessAliceDataStep1(readerPassport, writerPassport, keyK, keyA, 128)
	writerPassport.Close()

	return outputPartner.String(), outputPassport.String()
}

func partnerStep2(keyB *crypto.ECDHKey, originalInput, aliceEncrypted, bobEncryptedY string) string {
	readerPartnerEnc := psio.NewTSVReader(newMemReadCloser(bobEncryptedY))
	defer readerPartnerEnc.Close()
	bobEncMap, _ := commands.LoadIndexedData(readerPartnerEnc)

	readerOriginal := psio.NewTSVReader(newMemReadCloser(originalInput))
	defer readerOriginal.Close()
	originalData, _ := commands.LoadOriginalData(readerOriginal)

	readerPassport := psio.NewTSVReader(newMemReadCloser(aliceEncrypted))
	defer readerPassport.Close()

	output := newMemWriteCloser()
	writer := psio.NewTSVWriter(output)
	defer writer.Close()

	commands.ProcessBobStep2(readerPassport, writer, keyB, bobEncMap, originalData, 512)

	writer.Close()
	return output.String()
}
