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

var BobStep1Cmd = &cobra.Command{
	Use:   "bob-step1",
	Short: "Bob Step 1: генерация ключей и шифрование телефонов",
	RunE:  runBobStep1,
}

var (
	bobStep1Input      string
	bobStep1OutHMACKey string
	bobStep1OutECDHKey string
	bobStep1OutEnc     string
)

func init() {
	BobStep1Cmd.Flags().StringVarP(&bobStep1Input, "input", "i", "bob_data.tsv", "Входной TSV файл (phone tab b_user_id)")
	BobStep1Cmd.Flags().StringVar(&bobStep1OutHMACKey, "out-hmac-key", "bob_hmac_key.txt", "Выходной файл с HMAC ключом K (для передачи)")
	BobStep1Cmd.Flags().StringVar(&bobStep1OutECDHKey, "out-ecdh-key", "bob_ecdh_key.txt", "Выходной файл с ECDH ключом B (приватный)")
	BobStep1Cmd.Flags().StringVarP(&bobStep1OutEnc, "out-encrypted", "e", "bob_encrypted.tsv.gz", "Выходной файл с index и H(phone)^B (для передачи)")
}

func runBobStep1(cmd *cobra.Command, args []string) error {
	keyK, err := crypto.GenerateHMACKey()
	if err != nil {
		return fmt.Errorf("ошибка генерации HMAC ключа: %w", err)
	}

	keyB, err := crypto.GenerateECDHKey()
	if err != nil {
		return fmt.Errorf("ошибка генерации ECDH ключа: %w", err)
	}

	if err := crypto.SaveHMACKey(bobStep1OutHMACKey, keyK); err != nil {
		return fmt.Errorf("ошибка сохранения HMAC ключа: %w", err)
	}

	if err := crypto.SaveECDHKey(bobStep1OutECDHKey, keyB); err != nil {
		return fmt.Errorf("ошибка сохранения ECDH ключа: %w", err)
	}

	reader, err := io.OpenTSVFile(bobStep1Input)
	if err != nil {
		return fmt.Errorf("ошибка открытия входного файла: %w", err)
	}
	defer reader.Close()

	writer, err := io.CreateTSVFile(bobStep1OutEnc)
	if err != nil {
		return fmt.Errorf("ошибка создания выходного файла: %w", err)
	}
	defer writer.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	progress.TrackProgress(ctx, &wg, "Прогресс обработки", reader)

	count, err := ProcessBobStep1(reader, writer, keyK, keyB)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("ошибка финализации записи: %w", err)
	}

	cancel()
	wg.Wait()

	fmt.Fprintf(os.Stderr, "Обработано записей: %d\n", count)
	fmt.Fprintf(os.Stderr, "HMAC ключ K (для передачи): %s\n", bobStep1OutHMACKey)
	fmt.Fprintf(os.Stderr, "ECDH ключ B (приватный): %s\n", bobStep1OutECDHKey)
	fmt.Fprintf(os.Stderr, "Зашифрованные данные: %s\n", bobStep1OutEnc)

	return nil
}

func ProcessBobStep1(reader *io.TSVReader, writer *io.TSVWriter, keyK []byte, keyB *crypto.ECDHKey) (int, error) {
	count := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("ошибка чтения записи: %w", err)
		}

		if len(record) != 2 {
			return count, fmt.Errorf("неверный формат записи: ожидается 2 поля, получено %d", len(record))
		}

		phone := record[0]

		if err := validation.ValidateE164Phone(phone); err != nil {
			return count, fmt.Errorf("строка %d: %w", count, err)
		}

		hashed := crypto.HMAC(keyK, []byte(phone))

		encrypted, err := crypto.ECDHApply(keyB, hashed)
		if err != nil {
			return count, fmt.Errorf("ошибка ECDH шифрования: %w", err)
		}

		if err := writer.Write([]string{
			fmt.Sprintf("%d", count),
			encrypted,
		}); err != nil {
			return count, fmt.Errorf("ошибка записи: %w", err)
		}

		count++
	}

	return count, nil
}
