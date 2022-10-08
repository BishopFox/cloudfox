package main

import (
	"os"

	"github.com/BishopFox/cloudfox/cli"
	"github.com/BishopFox/cloudfox/utils"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:     os.Args[0],
		Version: "1.8.0",
	}
)

func main() {
	logfile := utils.InitLogging()
	defer logfile.Close()

	rootCmd.AddCommand(cli.AWSCommands, cli.AzCommands)
	rootCmd.Execute()
}
