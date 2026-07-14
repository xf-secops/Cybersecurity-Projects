/*
©AngelaMos | 2026
root.go

Cobra root command and CLI entry wiring for crypha
*/

package cli

import (
	"fmt"
	"os"

	"github.com/CarterPerez-dev/crypha/internal/config"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:     config.BinaryName,
	Short:   config.ShortDescription,
	Long:    config.LongDescription,
	Version: config.Version,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.SetVersionTemplate(config.BinaryName + " {{.Version}}\n")
}
