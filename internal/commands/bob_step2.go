package commands

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/progress"
	"github.com/pkositsyn/psi/internal/workerpool"
	"github.com/spf13/cobra"
)

var BobStep2Cmd = &cobra.Command{
	Use:   "bob-step2",
	Short: "Bob Step 2: вычисление пересечения и маппинг",
	RunE:  runBobStep2,
}

var (
	bobStep2InputECDHKey  string
	bobStep2InputOriginal string
	bobStep2InputAliceEnc string
	bobStep2InputBobEnc   string
	bobStep2Output        string
	bobStep2BatchSize     int
)

func init() {
	BobStep2Cmd.Flags().StringVar(&bobStep2InputECDHKey, "in-ecdh-key", "bob_ecdh_key.txt", "Файл с ECDH ключом B")
	BobStep2Cmd.Flags().StringVar(&bobStep2InputOriginal, "in-original", "bob_data.tsv", "Оригинальный входной файл (phone tab b_user_id)")
	BobStep2Cmd.Flags().StringVar(&bobStep2InputAliceEnc, "in-alice-enc", "alice_encrypted.tsv.gz", "Файл H(phone_a)^A от alice")
	BobStep2Cmd.Flags().StringVar(&bobStep2InputBobEnc, "in-bob-enc", "bob_encrypted_a.tsv.gz", "Файл H(phone_b)^B^A от alice")
	BobStep2Cmd.Flags().StringVar(&bobStep2Output, "output", "bob_final.tsv.gz", "Выходной файл b_user_id <-> H(phone_a)^A^B")
	BobStep2Cmd.Flags().IntVar(&bobStep2BatchSize, "batch-size", 128, "Размер батча для параллельной обработки")
}

func runBobStep2(cmd *cobra.Command, args []string) error {
	keyB, err := crypto.LoadECDHKey(bobStep2InputECDHKey)
	if err != nil {
		return fmt.Errorf("ошибка загрузки ECDH ключа B: %w", err)
	}

	bobEncMap, err := loadIndexedData(bobStep2InputBobEnc)
	if err != nil {
		return fmt.Errorf("ошибка загрузки H(phone_b)^B^A: %w", err)
	}

	originalData, err := loadOriginalData(bobStep2InputOriginal)
	if err != nil {
		return fmt.Errorf("ошибка загрузки оригинальных данных: %w", err)
	}

	if err := processAndMatch(keyB, bobStep2InputAliceEnc, bobStep2Output, bobEncMap, originalData, bobStep2BatchSize); err != nil {
		return fmt.Errorf("ошибка обработки и маппинга: %w", err)
	}

	fmt.Fprintf(os.Stderr, "Результат сохранен: %s\n", bobStep2Output)
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

		bUserID := record[1]
		result[fmt.Sprintf("%d", index)] = bUserID
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

type bobStep2Task struct {
	index      string
	encryptedA string
}

type bobStep2Result struct {
	index       string
	encryptedAB string
	bUserID     string
	matched     bool
}

func ProcessBobStep2(reader *io.TSVReader, writer *io.TSVWriter, keyB *crypto.ECDHKey, bobEncMap, originalData map[string]string, batchSize int) (int, int, error) {
	handler := func(task bobStep2Task) (bobStep2Result, error) {
		encryptedAB, err := crypto.ECDHApply(keyB, task.encryptedA)
		if err != nil {
			return bobStep2Result{}, err
		}

		var bUserID string
		matched := false
		if bobIndex, found := bobEncMap[encryptedAB]; found {
			if uid, ok := originalData[bobIndex]; ok {
				bUserID = uid
				matched = true
			}
		}

		return bobStep2Result{
			index:       task.index,
			encryptedAB: encryptedAB,
			bUserID:     bUserID,
			matched:     matched,
		}, nil
	}

	pool := workerpool.New(handler)

	var writeErr error
	var wg sync.WaitGroup
	matchedCount := 0

	wg.Go(func() {
		for result := range pool.Results() {
			if result.Error != nil {
				if writeErr == nil {
					writeErr = result.Error
				}
				continue
			}
			if writeErr == nil {
				if err := writer.Write([]string{result.Value.index, result.Value.encryptedAB, result.Value.bUserID}); err != nil {
					writeErr = err
				}
				if result.Value.matched {
					matchedCount++
				}
			}
		}
	})

	count := 0
	batch := make([]bobStep2Task, 0, batchSize)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			pool.Close()
			wg.Wait()
			return count, matchedCount, err
		}

		if len(record) < 2 {
			pool.Close()
			wg.Wait()
			return count, matchedCount, fmt.Errorf("неверный формат записи")
		}

		batch = append(batch, bobStep2Task{
			index:      record[0],
			encryptedA: record[1],
		})
		count++

		if len(batch) >= batchSize {
			pool.Add(batch)
			batch = make([]bobStep2Task, 0, batchSize)
		}
	}

	if len(batch) > 0 {
		pool.Add(batch)
	}

	pool.Close()
	wg.Wait()

	if writeErr != nil {
		return count, matchedCount, writeErr
	}

	return count, matchedCount, nil
}

func processAndMatch(keyB *crypto.ECDHKey, inputFile, outputFile string, bobEncMap, originalData map[string]string, batchSize int) error {
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var wg sync.WaitGroup
	progress.TrackProgress(ctx, &wg, "Прогресс обработки", reader)

	count, matched, err := ProcessBobStep2(reader, writer, keyB, bobEncMap, originalData, batchSize)
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
