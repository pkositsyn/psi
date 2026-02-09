package commands

import (
	"fmt"
	"os"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/validation"
	"github.com/spf13/cobra"
)

var PartnerStep1Cmd = &cobra.Command{
	Use:   "partner-step1",
	Short: "Partner Step 1: генерация ключей и шифрование телефонов",
	RunE:  runPartnerStep1,
}

var (
	partnerStep1Input      string
	partnerStep1OutHMACKey string
	partnerStep1OutECDHKey string
	partnerStep1OutEnc     string
)

func init() {
	PartnerStep1Cmd.Flags().StringVarP(&partnerStep1Input, "input", "i", "", "Входной TSV файл (phone tab user_id)")
	PartnerStep1Cmd.Flags().StringVar(&partnerStep1OutHMACKey, "out-hmac-key", "partner_hmac_key.txt", "Выходной файл с HMAC ключом K (для передачи)")
	PartnerStep1Cmd.Flags().StringVar(&partnerStep1OutECDHKey, "out-ecdh-key", "partner_ecdh_key.txt", "Выходной файл с ECDH ключом P (приватный)")
	PartnerStep1Cmd.Flags().StringVarP(&partnerStep1OutEnc, "out-encrypted", "e", "partner_encrypted.tsv.gz", "Выходной файл с index и H(phone)^P (для передачи)")
	PartnerStep1Cmd.MarkFlagRequired("input")
}

func runPartnerStep1(cmd *cobra.Command, args []string) error {
	keyK, err := crypto.GenerateHMACKey()
	if err != nil {
		return fmt.Errorf("ошибка генерации HMAC ключа: %w", err)
	}

	keyP, err := crypto.GenerateECDHKey()
	if err != nil {
		return fmt.Errorf("ошибка генерации ECDH ключа: %w", err)
	}

	if err := crypto.SaveHMACKey(partnerStep1OutHMACKey, keyK); err != nil {
		return fmt.Errorf("ошибка сохранения HMAC ключа: %w", err)
	}

	if err := crypto.SaveECDHKey(partnerStep1OutECDHKey, keyP); err != nil {
		return fmt.Errorf("ошибка сохранения ECDH ключа: %w", err)
	}

	reader, err := io.OpenTSVFile(partnerStep1Input)
	if err != nil {
		return fmt.Errorf("ошибка открытия входного файла: %w", err)
	}
	defer reader.Close()

	writer, err := io.CreateTSVFile(partnerStep1OutEnc)
	if err != nil {
		return fmt.Errorf("ошибка создания выходного файла: %w", err)
	}
	defer writer.Close()

	count, err := ProcessPartnerStep1(reader, writer, keyK, keyP)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("ошибка финализации записи: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Обработано записей: %d\n", count)
	fmt.Fprintf(os.Stderr, "HMAC ключ K (для передачи): %s\n", partnerStep1OutHMACKey)
	fmt.Fprintf(os.Stderr, "ECDH ключ P (приватный): %s\n", partnerStep1OutECDHKey)
	fmt.Fprintf(os.Stderr, "Зашифрованные данные: %s\n", partnerStep1OutEnc)

	return nil
}

func ProcessPartnerStep1(reader *io.TSVReader, writer *io.TSVWriter, keyK []byte, keyP *crypto.ECDHKey) (int, error) {
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

		encrypted, err := crypto.ECDHApply(keyP, hashed)
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
