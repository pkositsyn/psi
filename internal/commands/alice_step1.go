package commands

import (
	"fmt"
	"os"
	"sync"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/validation"
	"github.com/spf13/cobra"
)

var AliceStep1Cmd = &cobra.Command{
	Use:   "alice-step1",
	Short: "Alice Step 1: обработка данных от bob и генерация своих данных",
	RunE:  runAliceStep1,
}

var (
	aliceStep1InputHMACKey string
	aliceStep1InputEnc     string
	aliceStep1InputPuid    string
	aliceStep1OutECDHKey   string
	aliceStep1OutEncBob    string
	aliceStep1OutEncAlice  string
)

func init() {
	AliceStep1Cmd.Flags().StringVar(&aliceStep1InputHMACKey, "in-hmac-key", "bob_hmac_key.txt", "Входной файл с HMAC ключом K от bob")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1InputEnc, "in-encrypted", "bob_encrypted.tsv.gz", "Входной файл H(phone_b)^B от bob")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1InputPuid, "in-a_user_id", "alice_data.tsv", "Входной файл с phone_a и a_user_id")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1OutECDHKey, "out-ecdh-key", "alice_ecdh_key.txt", "Выходной файл с ECDH ключом A (приватный)")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1OutEncBob, "out-encrypted-bob", "bob_encrypted_a.tsv.gz", "Выходной файл H(phone_b)^B^A")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1OutEncAlice, "out-encrypted-alice", "alice_encrypted.tsv.gz", "Выходной файл a_user_id <-> H(phone_a)^A")
	AliceStep1Cmd.MarkFlagRequired("in-hmac-key")
	AliceStep1Cmd.MarkFlagRequired("in-encrypted")
	AliceStep1Cmd.MarkFlagRequired("in-a_user_id")
}

func runAliceStep1(cmd *cobra.Command, args []string) error {
	keyK, err := crypto.LoadHMACKey(aliceStep1InputHMACKey)
	if err != nil {
		return fmt.Errorf("ошибка загрузки HMAC ключа K: %w", err)
	}

	keyA, err := crypto.GenerateECDHKey()
	if err != nil {
		return fmt.Errorf("ошибка генерации ECDH ключа A: %w", err)
	}

	if err := crypto.SaveECDHKey(aliceStep1OutECDHKey, keyA); err != nil {
		return fmt.Errorf("ошибка сохранения ECDH ключа A: %w", err)
	}

	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(2)
	go func() {
		defer wg.Done()
		errChan <- processBobData(keyA, aliceStep1InputEnc, aliceStep1OutEncBob)
	}()

	go func() {
		defer wg.Done()
		errChan <- processAliceData(keyK, keyA, aliceStep1InputPuid, aliceStep1OutEncAlice)
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if err != nil {
			return fmt.Errorf("ошибка обработки данных: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "ECDH ключ A (приватный): %s\n", aliceStep1OutECDHKey)
	fmt.Fprintf(os.Stderr, "H(phone_b)^B^A сохранен: %s\n", aliceStep1OutEncBob)
	fmt.Fprintf(os.Stderr, "H(phone_a)^A сохранен: %s\n", aliceStep1OutEncAlice)

	return nil
}

func ProcessBobDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyA *crypto.ECDHKey) (int, error) {
	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		if len(record) < 2 {
			return count, fmt.Errorf("неверный формат записи")
		}

		index := record[0]
		encryptedB := record[1]

		encryptedBA, err := crypto.ECDHApply(keyA, encryptedB)
		if err != nil {
			return count, err
		}

		if err := writer.Write([]string{index, encryptedBA}); err != nil {
			return count, err
		}

		count++
	}

	return count, nil
}

func processBobData(keyA *crypto.ECDHKey, inputFile, outputFile string) error {
	reader, err := io.OpenTSVFile(inputFile)
	if err != nil {
		return err
	}
	defer reader.Close()

	writer, err := io.CreateTSVFile(outputFile)
	if err != nil {
		return err
	}
	defer writer.Close()

	count, err := ProcessBobDataStep1(reader, writer, keyA)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Обработано записей от bob: %d\n", count)
	return nil
}

func ProcessAliceDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyK []byte, keyA *crypto.ECDHKey) (int, error) {
	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, err
		}

		if len(record) != 2 {
			return count, fmt.Errorf("неверный формат записи")
		}

		phone := record[0]
		a_user_id := record[1]

		if err := validation.ValidateE164Phone(phone); err != nil {
			return count, fmt.Errorf("строка %d: %w", count, err)
		}

		hashed := crypto.HMAC(keyK, []byte(phone))

		encrypted, err := crypto.ECDHApply(keyA, hashed)
		if err != nil {
			return count, err
		}

		if err := writer.Write([]string{
			fmt.Sprintf("%d", count),
			a_user_id,
			encrypted,
		}); err != nil {
			return count, err
		}

		count++
	}

	return count, nil
}

func processAliceData(keyK []byte, keyA *crypto.ECDHKey, inputFile, outputFile string) error {
	reader, err := io.OpenTSVFile(inputFile)
	if err != nil {
		return err
	}
	defer reader.Close()

	writer, err := io.CreateTSVFile(outputFile)
	if err != nil {
		return err
	}
	defer writer.Close()

	count, err := ProcessAliceDataStep1(reader, writer, keyK, keyA)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Обработано записей alice: %d\n", count)
	return nil
}
