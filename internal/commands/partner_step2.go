package commands

import (
	"fmt"
	"os"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/spf13/cobra"
)

var PartnerStep2Cmd = &cobra.Command{
	Use:   "partner-step2",
	Short: "Partner Step 2: вычисление пересечения и маппинг",
	RunE:  runPartnerStep2,
}

var (
	partnerStep2InputECDHKey     string
	partnerStep2InputOriginal    string
	partnerStep2InputPassportEnc string
	partnerStep2InputPartnerEnc  string
	partnerStep2Output           string
)

func init() {
	PartnerStep2Cmd.Flags().StringVar(&partnerStep2InputECDHKey, "in-ecdh-key", "", "Файл с ECDH ключом P")
	PartnerStep2Cmd.Flags().StringVar(&partnerStep2InputOriginal, "in-original", "", "Оригинальный входной файл (phone tab user_id)")
	PartnerStep2Cmd.Flags().StringVar(&partnerStep2InputPassportEnc, "in-passport-enc", "", "Файл H(phone_ya)^Y от passport")
	PartnerStep2Cmd.Flags().StringVar(&partnerStep2InputPartnerEnc, "in-partner-enc", "", "Файл H(phone_p)^P^Y от passport")
	PartnerStep2Cmd.Flags().StringVar(&partnerStep2Output, "output", "partner_final.tsv.gz", "Выходной файл user_id <-> H(phone_ya)^Y^P")
	PartnerStep2Cmd.MarkFlagRequired("in-ecdh-key")
	PartnerStep2Cmd.MarkFlagRequired("in-original")
	PartnerStep2Cmd.MarkFlagRequired("in-passport-enc")
	PartnerStep2Cmd.MarkFlagRequired("in-partner-enc")
}

func runPartnerStep2(cmd *cobra.Command, args []string) error {
	keyP, err := crypto.LoadECDHKey(partnerStep2InputECDHKey)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ECDH ключа P: %w", err)
	}

	partnerEncMap, err := loadIndexedData(partnerStep2InputPartnerEnc)
	if err != nil {
		return fmt.Errorf("ошибка загрузки H(phone_p)^P^Y: %w", err)
	}

	originalData, err := loadOriginalData(partnerStep2InputOriginal)
	if err != nil {
		return fmt.Errorf("ошибка загрузки оригинальных данных: %w", err)
	}

	if err := processAndMatch(keyP, partnerStep2InputPassportEnc, partnerStep2Output, partnerEncMap, originalData); err != nil {
		return fmt.Errorf("ошибка обработки и маппинга: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Результат сохранен: %s\n", partnerStep2Output)
	return nil
}

func LoadIndexedData(reader *io.TSVReader) (map[string]string, error) {
	result := make(map[string]string)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) < 2 {
			continue
		}

		index := record[0]
		value := record[1]
		result[value] = index
	}

	return result, nil
}

func loadIndexedData(filename string) (map[string]string, error) {
	reader, err := io.OpenTSVFile(filename)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return LoadIndexedData(reader)
}

func LoadOriginalData(reader *io.TSVReader) (map[string]string, error) {
	result := make(map[string]string)

	index := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) < 2 {
			continue
		}

		userID := record[1]
		result[fmt.Sprintf("%d", index)] = userID
		index++
	}

	return result, nil
}

func loadOriginalData(filename string) (map[string]string, error) {
	reader, err := io.OpenTSVFile(filename)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return LoadOriginalData(reader)
}

func ProcessPartnerStep2(reader *io.TSVReader, writer *io.TSVWriter, keyP *crypto.ECDHKey, partnerEncMap, originalData map[string]string) (int, int, error) {
	count := 0
	matched := 0
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, matched, err
		}

		if len(record) < 3 {
			return count, matched, fmt.Errorf("неверный формат записи")
		}

		index := record[0]
		encryptedY := record[2]

		encryptedYP, err := crypto.ECDHApply(keyP, encryptedY)
		if err != nil {
			return count, matched, err
		}

		userID := ""
		if partnerIndex, found := partnerEncMap[encryptedYP]; found {
			if uid, ok := originalData[partnerIndex]; ok {
				userID = uid
				matched++
			}
		}

		if err := writer.Write([]string{index, encryptedYP, userID}); err != nil {
			return count, matched, err
		}

		count++
	}

	return count, matched, nil
}

func processAndMatch(keyP *crypto.ECDHKey, inputFile, outputFile string, partnerEncMap, originalData map[string]string) error {
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

	count, matched, err := ProcessPartnerStep2(reader, writer, keyP, partnerEncMap, originalData)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Обработано записей: %d, совпадений: %d\n", count, matched)
	return nil
}
