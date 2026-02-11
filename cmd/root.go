package cmd

import (
	"fmt"
	"os"

	"github.com/pkositsyn/psi/internal/commands"
	"github.com/pkositsyn/psi/internal/maxprocs"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "psi",
	Short: "Private Set Intersection утилита для безопасного обмена данными",
	Long: `PSI - утилита для выполнения криптографического протокола Private Set Intersection
с использованием HMAC-SHA256 и ECDH SECP256R1`,
}

func init() {
	rootCmd.AddCommand(commands.BobStep1Cmd)
	rootCmd.AddCommand(commands.BobStep2Cmd)
	rootCmd.AddCommand(commands.AliceStep1Cmd)
	rootCmd.AddCommand(commands.AliceStep2Cmd)
	rootCmd.AddCommand(commands.ValidateCmd)
}

func Execute() {
	// Save some CPU for background work
	maxprocs.Adjust()

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
