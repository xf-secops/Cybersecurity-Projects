// ©AngelaMos | 2026
// root.go

package main

import (
	"github.com/spf13/cobra"

	"github.com/CarterPerez-dev/nadezhda/internal/config"
)

var (
	flagConfig string
	flagDB     string
)

var rootCmd = &cobra.Command{
	Use:          "nadezhda",
	Short:        "Security news and CVE aggregation engine",
	Long:         "Nadezhda aggregates cybersecurity news, enriches CVEs with NVD, CISA KEV, and EPSS intelligence, clusters stories across outlets, and ranks what matters.",
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagConfig, "config", "", "path to config.yaml (optional)")
	rootCmd.PersistentFlags().StringVar(&flagDB, "db", "", "override database path")
}

func loadConfig() (config.Config, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return config.Config{}, err
	}
	if flagDB != "" {
		cfg.DBPath = flagDB
	}
	return cfg, nil
}
