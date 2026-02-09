package commands

import (
	"fmt"
	"os"

	"github.com/pkositsyn/psi/internal/io"
	"github.com/spf13/cobra"
)

var PassportStep2Cmd = &cobra.Command{
	Use:   "passport-step2",
	Short: "Passport Step 2: финальный маппинг puid <-> user_id",
	RunE:  runPassportStep2,
}

var (
	passportStep2InputOriginal string
	passportStep2InputPartner  string
	passportStep2Output        string
)

func init() {
	PassportStep2Cmd.Flags().StringVar(&passportStep2InputOriginal, "in-original", "", "Файл puid <-> H(phone_ya)^Y из step1")
	PassportStep2Cmd.Flags().StringVar(&passportStep2InputPartner, "in-partner", "", "Файл user_id <-> H(phone_ya)^Y^P от partner")
	PassportStep2Cmd.Flags().StringVar(&passportStep2Output, "output", "passport_final.tsv.gz", "Выходной файл puid <-> user_id")
	PassportStep2Cmd.MarkFlagRequired("in-original")
	PassportStep2Cmd.MarkFlagRequired("in-partner")
}

func runPassportStep2(cmd *cobra.Command, args []string) error {
	partnerData, err := loadPartnerFinalData(passportStep2InputPartner)
	if err != nil {
		return fmt.Errorf("ошибка загрузки данных от partner: %w", err)
	}

	if err := createFinalMapping(passportStep2InputOriginal, passportStep2Output, partnerData); err != nil {
		return fmt.Errorf("ошибка создания финального маппинга: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Финальный маппинг сохранен: %s\n", passportStep2Output)
	return nil
}


type PartnerRecord struct {
	EncryptedYP string
	UserID      string
}

func LoadPartnerFinalData(reader *io.TSVReader) (map[string]PartnerRecord, error) {
	result := make(map[string]PartnerRecord)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		if len(record) < 3 {
			continue
		}

		index := record[0]
		encryptedYP := record[1]
		userID := record[2]

		result[index] = PartnerRecord{
			EncryptedYP: encryptedYP,
			UserID:      userID,
		}
	}

	return result, nil
}

func loadPartnerFinalData(filename string) (map[string]PartnerRecord, error) {
	reader, err := io.OpenTSVFile(filename)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return LoadPartnerFinalData(reader)
}

func ProcessPassportStep2(reader *io.TSVReader, writer *io.TSVWriter, partnerData map[string]PartnerRecord) (int, int, error) {
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
		puid := record[1]

		var userID string
		if pr, found := partnerData[index]; found && pr.UserID != "" {
			userID = pr.UserID
			matched++
		}

		if err := writer.Write([]string{puid, userID}); err != nil {
			return count, matched, err
		}

		count++
	}

	return count, matched, nil
}

func createFinalMapping(originalFile, outputFile string, partnerData map[string]PartnerRecord) error {
	reader, err := io.OpenTSVFile(originalFile)
	if err != nil {
		return err
	}
	defer reader.Close()

	writer, err := io.CreateTSVFile(outputFile)
	if err != nil {
		return err
	}
	defer writer.Close()

	count, matched, err := ProcessPassportStep2(reader, writer, partnerData)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Обработано записей: %d, совпадений: %d\n", count, matched)
	return nil
}
