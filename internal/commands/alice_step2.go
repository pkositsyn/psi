package commands

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/progress"
	"github.com/spf13/cobra"
)

var AliceStep2Cmd = &cobra.Command{
	Use:   "alice-step2",
	Short: "Alice Step 2: финальный маппинг a_user_id <-> b_user_id",
	RunE:  runAliceStep2,
}

var (
	aliceStep2InputOriginal string
	aliceStep2InputBob      string
	aliceStep2Output        string
)

func init() {
	AliceStep2Cmd.Flags().StringVar(&aliceStep2InputOriginal, "in-original", "alice_encrypted.tsv.gz", "Файл a_user_id <-> H(phone_a)^A из step1")
	AliceStep2Cmd.Flags().StringVar(&aliceStep2InputBob, "in-bob", "bob_final.tsv.gz", "Файл b_user_id <-> H(phone_a)^A^B от bob")
	AliceStep2Cmd.Flags().StringVar(&aliceStep2Output, "output", "alice_final.tsv.gz", "Выходной файл a_user_id <-> b_user_id")
}

func runAliceStep2(cmd *cobra.Command, args []string) error {
	bobData, err := loadBobFinalData(aliceStep2InputBob)
	if err != nil {
		return fmt.Errorf("ошибка загрузки данных от bob: %w", err)
	}

	if err := createFinalMapping(aliceStep2InputOriginal, aliceStep2Output, bobData); err != nil {
		return fmt.Errorf("ошибка создания финального маппинга: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Финальный маппинг сохранен: %s\n", aliceStep2Output)
	return nil
}

type BobRecord struct {
	EncryptedAB string
	UserID      string
}

func LoadBobFinalData(reader *io.TSVReader) (map[string]BobRecord, error) {
	result := make(map[string]BobRecord)

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
		encryptedAB := record[1]
		bUserID := record[2]

		result[index] = BobRecord{
			EncryptedAB: encryptedAB,
			UserID:      bUserID,
		}
	}

	return result, nil
}

func loadBobFinalData(filename string) (map[string]BobRecord, error) {
	reader, err := io.OpenTSVFile(filename)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	return LoadBobFinalData(reader)
}

func ProcessAliceStep2(reader *io.TSVReader, writer *io.TSVWriter, bobData map[string]BobRecord) (int, int, error) {
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
		a_user_id := record[1]

		var bUserID string
		if br, found := bobData[index]; found && br.UserID != "" {
			bUserID = br.UserID
			matched++
		}

		if err := writer.Write([]string{a_user_id, bUserID}); err != nil {
			return count, matched, err
		}

		count++
	}

	return count, matched, nil
}

func createFinalMapping(originalFile, outputFile string, bobData map[string]BobRecord) error {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	progress.TrackProgress(ctx, &wg, "Прогресс обработки", reader)

	count, matched, err := ProcessAliceStep2(reader, writer, bobData)
	if err != nil {
		return err
	}

	if err := writer.Close(); err != nil {
		return err
	}

	cancel()
	wg.Wait()

	fmt.Fprintf(os.Stderr, "Обработано записей: %d, совпадений: %d\n", count, matched)
	return nil
}
