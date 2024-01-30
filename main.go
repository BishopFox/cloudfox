package main

import (
	"os"

	"github.com/BishopFox/cloudfox/cli"
	"github.com/BishopFox/cloudfox/globals"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:     os.Args[0],
		Version: globals.CLOUDFOX_VERSION,
	}
)

func main() {
	rootCmd.AddCommand(cli.AWSCommands, cli.AzCommands)
	rootCmd.Execute()
}
