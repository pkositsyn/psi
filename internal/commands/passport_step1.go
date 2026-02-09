package commands

import (
	"fmt"
	"os"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/validation"
	"github.com/spf13/cobra"
)

var PassportStep1Cmd = &cobra.Command{
	Use:   "passport-step1",
	Short: "Passport Step 1: обработка данных от partner и генерация своих данных",
	RunE:  runPassportStep1,
}

var (
	passportStep1InputHMACKey   string
	passportStep1InputEnc       string
	passportStep1InputPuid      string
	passportStep1OutECDHKey     string
	passportStep1OutEncPartner  string
	passportStep1OutEncPassport string
)

func init() {
	PassportStep1Cmd.Flags().StringVar(&passportStep1InputHMACKey, "in-hmac-key", "", "Входной файл с HMAC ключом K от partner")
	PassportStep1Cmd.Flags().StringVar(&passportStep1InputEnc, "in-encrypted", "", "Входной файл H(phone_p)^P от partner")
	PassportStep1Cmd.Flags().StringVar(&passportStep1InputPuid, "in-puid", "", "Входной файл с puid и phone_ya")
	PassportStep1Cmd.Flags().StringVar(&passportStep1OutECDHKey, "out-ecdh-key", "passport_ecdh_key.txt", "Выходной файл с ECDH ключом Y (приватный)")
	PassportStep1Cmd.Flags().StringVar(&passportStep1OutEncPartner, "out-encrypted-partner", "partner_encrypted_y.tsv.gz", "Выходной файл H(phone_p)^P^Y")
	PassportStep1Cmd.Flags().StringVar(&passportStep1OutEncPassport, "out-encrypted-passport", "passport_encrypted.tsv.gz", "Выходной файл puid <-> H(phone_ya)^Y")
	PassportStep1Cmd.MarkFlagRequired("in-hmac-key")
	PassportStep1Cmd.MarkFlagRequired("in-encrypted")
	PassportStep1Cmd.MarkFlagRequired("in-puid")
}

func runPassportStep1(cmd *cobra.Command, args []string) error {
	keyK, err := crypto.LoadHMACKey(passportStep1InputHMACKey)
	if err != nil {
		return fmt.Errorf("ошибка загрузки HMAC ключа K: %w", err)
	}

	keyY, err := crypto.GenerateECDHKey()
	if err != nil {
		return fmt.Errorf("ошибка генерации ECDH ключа Y: %w", err)
	}

	if err := crypto.SaveECDHKey(passportStep1OutECDHKey, keyY); err != nil {
		return fmt.Errorf("ошибка сохранения ECDH ключа Y: %w", err)
	}

	errChan := make(chan error, 2)

	go func() {
		errChan <- processPartnerData(keyY, passportStep1InputEnc, passportStep1OutEncPartner)
	}()

	go func() {
		errChan <- processPassportData(keyK, keyY, passportStep1InputPuid, passportStep1OutEncPassport)
	}()

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			return fmt.Errorf("ошибка обработки данных: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "ECDH ключ Y (приватный): %s\n", passportStep1OutECDHKey)
	fmt.Fprintf(os.Stderr, "H(phone_p)^P^Y сохранен: %s\n", passportStep1OutEncPartner)
	fmt.Fprintf(os.Stderr, "H(phone_ya)^Y сохранен: %s\n", passportStep1OutEncPassport)

	return nil
}

func ProcessPartnerDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyY *crypto.ECDHKey) (int, error) {
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
		encryptedP := record[1]

		encryptedPY, err := crypto.ECDHApply(keyY, encryptedP)
		if err != nil {
			return count, err
		}

		if err := writer.Write([]string{index, encryptedPY}); err != nil {
			return count, err
		}

		count++
	}

	return count, nil
}

func processPartnerData(keyY *crypto.ECDHKey, inputFile, outputFile string) error {
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

	count, err := ProcessPartnerDataStep1(reader, writer, keyY)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Обработано записей от partner: %d\n", count)
	return nil
}

func ProcessPassportDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyK []byte, keyY *crypto.ECDHKey) (int, error) {
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

		puid := record[0]
		phone := record[1]

		if err := validation.ValidateE164Phone(phone); err != nil {
			return count, fmt.Errorf("строка %d: %w", count, err)
		}

		hashed := crypto.HMAC(keyK, []byte(phone))

		encrypted, err := crypto.ECDHApply(keyY, hashed)
		if err != nil {
			return count, err
		}

		if err := writer.Write([]string{
			fmt.Sprintf("%d", count),
			puid,
			encrypted,
		}); err != nil {
			return count, err
		}

		count++
	}

	return count, nil
}

func processPassportData(keyK []byte, keyY *crypto.ECDHKey, inputFile, outputFile string) error {
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

	count, err := ProcessPassportDataStep1(reader, writer, keyK, keyY)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Обработано записей passport: %d\n", count)
	return nil
}
