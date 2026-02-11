package commands

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"

	"github.com/pkositsyn/psi/internal/crypto"
	"github.com/pkositsyn/psi/internal/io"
	"github.com/pkositsyn/psi/internal/progress"
	"github.com/pkositsyn/psi/internal/validation"
	"github.com/pkositsyn/psi/internal/workerpool"
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
	aliceStep1BatchSize    int
)

func init() {
	AliceStep1Cmd.Flags().StringVar(&aliceStep1InputHMACKey, "in-hmac-key", "bob_hmac_key.txt", "Входной файл с HMAC ключом K от bob")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1InputEnc, "in-encrypted", "bob_encrypted.tsv.gz", "Входной файл H(phone_b)^B от bob")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1InputPuid, "in-auserid", "alice_data.tsv", "Входной файл с phone_a и a_user_id")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1OutECDHKey, "out-ecdh-key", "alice_ecdh_key.txt", "Выходной файл с ECDH ключом A (приватный)")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1OutEncBob, "out-encrypted-bob", "bob_encrypted_a.tsv.gz", "Выходной файл H(phone_b)^B^A")
	AliceStep1Cmd.Flags().StringVar(&aliceStep1OutEncAlice, "out-encrypted-alice", "alice_encrypted.tsv.gz", "Выходной файл a_user_id <-> H(phone_a)^A")
	AliceStep1Cmd.Flags().IntVar(&aliceStep1BatchSize, "batch-size", 128, "Размер батча для параллельной обработки")
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
	var wgProgress sync.WaitGroup
	progress.TrackProgress(ctx, &wgProgress, "Прогресс обработки", aliceReader, bobReader)

	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Go(func() {
		errChan <- ProcessBobDataStep1(bobReader, bobWriter, keyA, aliceStep1BatchSize)
	})

	wg.Go(func() {
		errChan <- ProcessAliceDataStep1(aliceReader, aliceWriter, keyK, keyA, aliceStep1BatchSize)
	})

	go func() {
		wg.Wait()
		cancel()
		wgProgress.Wait()
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

type bobDataTask struct {
	index      string
	encryptedB string
}

type bobDataResult struct {
	index       string
	encryptedBA string
}

func ProcessBobDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyA *crypto.ECDHKey, batchSize int) error {
	handler := func(task bobDataTask) (bobDataResult, error) {
		encryptedBA, err := crypto.ECDHApply(keyA, task.encryptedB)
		if err != nil {
			return bobDataResult{}, err
		}

		return bobDataResult{
			index:       task.index,
			encryptedBA: encryptedBA,
		}, nil
	}

	pool := workerpool.New(handler)

	var writeErr error
	var wg sync.WaitGroup

	wg.Go(func() {
		for result := range pool.Results() {
			if result.Error != nil {
				if writeErr == nil {
					writeErr = result.Error
				}
				continue
			}
			if writeErr == nil {
				if err := writer.Write([]string{result.Value.index, result.Value.encryptedBA}); err != nil {
					writeErr = err
				}
			}
		}
	})

	batch := make([]bobDataTask, 0, batchSize)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			pool.Close()
			wg.Wait()
			return err
		}

		if len(record) < 2 {
			pool.Close()
			wg.Wait()
			return fmt.Errorf("неверный формат записи")
		}

		batch = append(batch, bobDataTask{
			index:      record[0],
			encryptedB: record[1],
		})

		if len(batch) >= batchSize {
			pool.Add(batch)
			batch = make([]bobDataTask, 0, batchSize)
		}
	}

	if len(batch) > 0 {
		pool.Add(batch)
	}

	pool.Close()
	wg.Wait()

	if writeErr != nil {
		return writeErr
	}

	return nil
}

type aliceDataTask struct {
	index   int
	phone   string
	aUserId string
}

type aliceDataResult struct {
	index     int
	aUserId   string
	encrypted string
}

func ProcessAliceDataStep1(reader *io.TSVReader, writer *io.TSVWriter, keyK []byte, keyA *crypto.ECDHKey, batchSize int) error {
	hmacPool := &sync.Pool{
		New: func() any {
			return hmac.New(sha256.New, keyK)
		},
	}

	handler := func(task aliceDataTask) (aliceDataResult, error) {
		if err := validation.ValidateE164Phone(task.phone); err != nil {
			return aliceDataResult{}, fmt.Errorf("строка %d: %w", task.index, err)
		}

		hashed := crypto.HMAC(hmacPool, keyK, []byte(task.phone))

		encrypted, err := crypto.ECDHApply(keyA, hashed)
		if err != nil {
			return aliceDataResult{}, err
		}

		return aliceDataResult{
			index:     task.index,
			aUserId:   task.aUserId,
			encrypted: encrypted,
		}, nil
	}

	pool := workerpool.New(handler)

	var writeErr error
	var wg sync.WaitGroup

	wg.Go(func() {
		for result := range pool.Results() {
			if result.Error != nil {
				if writeErr == nil {
					writeErr = result.Error
				}
				continue
			}
			if writeErr == nil {
				if err := writer.Write([]string{
					fmt.Sprintf("%d", result.Value.index),
					result.Value.aUserId,
					result.Value.encrypted,
				}); err != nil {
					writeErr = err
				}
			}
		}
	})

	count := 0
	batch := make([]aliceDataTask, 0, batchSize)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			pool.Close()
			wg.Wait()
			return err
		}

		if len(record) != 2 {
			pool.Close()
			wg.Wait()
			return fmt.Errorf("неверный формат записи")
		}

		batch = append(batch, aliceDataTask{
			index:   count,
			phone:   record[0],
			aUserId: record[1],
		})
		count++

		if len(batch) >= batchSize {
			pool.Add(batch)
			batch = make([]aliceDataTask, 0, batchSize)
		}
	}

	if len(batch) > 0 {
		pool.Add(batch)
	}

	pool.Close()
	wg.Wait()

	if writeErr != nil {
		return writeErr
	}

	return nil
}
