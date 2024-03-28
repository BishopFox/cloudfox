package main

import (
	"log"
	"os"
	"runtime/pprof"

	"github.com/BishopFox/cloudfox/cli"
	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{
		Use:     os.Args[0],
		Version: "1.14.0-prerelease",
	}
)

func main() {
	cpuProfile := "cpu.prof"
	f, err := os.Create(cpuProfile)
	if err != nil {
		log.Fatal("could not create CPU profile: ", err)
	}
	if err := pprof.StartCPUProfile(f); err != nil {
		log.Fatal("could not start CPU profile: ", err)
	}
	defer pprof.StopCPUProfile()

	// Your program's main execution logic here
	rootCmd.AddCommand(cli.AWSCommands, cli.AzCommands)
	rootCmd.Execute()
}
