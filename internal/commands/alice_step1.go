package commands

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/progress"
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

	bobReader, err := io.OpenTSVFile(aliceStep1InputEnc)
	if err != nil {
		return err
	}
	defer bobReader.Close()

	bobWriter, err := io.CreateTSVFile(aliceStep1OutEncBob)
	if err != nil {
		return err
	}
	defer bobWriter.Close()

	aliceReader, err := io.OpenTSVFile(aliceStep1InputPuid)
	if err != nil {
		return err
	}
	defer aliceReader.Close()

	aliceWriter, err := io.CreateTSVFile(aliceStep1OutEncAlice)
	if err != nil {
		return err
	}
	defer aliceWriter.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	progress.TrackProgress(ctx, &wg, "Прогресс обработки", aliceReader, bobReader)

	errChan := make(chan error, 2)

	wg.Go(func() {
		errChan <- ProcessBobDataStep1(bobReader, bobWriter, keyA)
	})

	wg.Go(func() {
		errChan <- ProcessAliceDataStep1(aliceReader, aliceWriter, keyK, keyA)
	})

	go func() {
		cancel()
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

func ProcessBobDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyA *crypto.ECDHKey) error {
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) < 2 {
			return fmt.Errorf("неверный формат записи")
		}

		index := record[0]
		encryptedB := record[1]

		encryptedBA, err := crypto.ECDHApply(keyA, encryptedB)
		if err != nil {
			return err
		}

		if err := writer.Write([]string{index, encryptedBA}); err != nil {
			return err
		}
	}

	return nil
}

func ProcessAliceDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyK []byte, keyA *crypto.ECDHKey) error {
	var count int
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if len(record) != 2 {
			return fmt.Errorf("неверный формат записи")
		}

		phone := record[0]
		a_user_id := record[1]

		if err := validation.ValidateE164Phone(phone); err != nil {
			return fmt.Errorf("строка %d: %w", count, err)
		}

		hashed := crypto.HMAC(keyK, []byte(phone))

		encrypted, err := crypto.ECDHApply(keyA, hashed)
		if err != nil {
			return err
		}

		if err := writer.Write([]string{
			fmt.Sprintf("%d", count),
			a_user_id,
			encrypted,
		}); err != nil {
			return err
		}

		count++
	}

	return nil
}
