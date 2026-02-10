package commands

import (
	"fmt"
	"os"

	"github.com/pkositsyn/psi/internal/io"
	"github.com/spf13/cobra"
)

var ValidateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Валидация файлов данных",
	RunE:  runValidate,
}

var (
	validateInput string
)

func init() {
	ValidateCmd.Flags().StringVarP(&validateInput, "input", "i", "", "Входной файл для валидации")
	ValidateCmd.MarkFlagRequired("input")
}

func runValidate(cmd *cobra.Command, args []string) error {
	reader, err := io.OpenTSVFile(validateInput)
	if err != nil {
		return fmt.Errorf("ошибка открытия файла: %w", err)
	}
	defer reader.Close()

	count := 0
	fieldCounts := make(map[int]int)

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("ошибка чтения записи %d: %w", count, err)
		}

		fieldCounts[len(record)]++
		count++
	}

	fmt.Fprintf(os.Stderr, "Файл валиден: %s\n", validateInput)
	fmt.Fprintf(os.Stderr, "Всего записей: %d\n", count)
	fmt.Fprintf(os.Stderr, "Распределение по количеству полей:\n")
	for fields, cnt := range fieldCounts {
		fmt.Fprintf(os.Stderr, "  %d полей: %d записей\n", fields, cnt)
	}

	return nil
}
