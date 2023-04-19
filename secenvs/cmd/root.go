package cmd

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "secenvs",
	Short: "Processes secure environment variables",
	Long: `Scans environment variables for any that
require their values extracting via some other process,
such as 'pass show …', for example.`,
	Run: rootRun,
}

func rootRun(cmd *cobra.Command, args []string) {
	fmt.Println()

	for _, e := range os.Environ() {
		envSplit := strings.SplitN(e, "=", 2)
		varName := envSplit[0]
		varValue := envSplit[1]

		// Only process env vars that start with a processor name.
		// For now, we only support pass
		match, err := regexp.MatchString("^pass:", varValue)
		if err != nil {
			log.Fatalln("Unable to perform regex check for processor pattern on ", varName)
		}
		if !match {
			continue
		}

		// Look up the env var value using the processor
		processSplit := strings.SplitN(varValue, ":", 2)

		secret := process(processSplit[0], processSplit[1])

		fmt.Println("export " + varName + "=" + secret)
	}
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.secenvs.yaml)")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func process(processor string, secretKey string) string {
	switch processor {
	case "pass":
		return processPassIdentifier(secretKey)
	default:
		return processor + ":" + secretKey
	}
}

func processPassIdentifier(secretKey string) string {
	var stdout, stderr bytes.Buffer

	// If this fails with the error
	cmdString := "pass show " + secretKey + " | head --line 1"
	command := exec.Command("sh", "-c", cmdString)
	command.Stdin = strings.NewReader("")
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	if err != nil {
		log.Fatalln(fmt.Errorf("%s: %s", err, stderr.String()))
	}

	return strings.TrimRight(stdout.String(), "\n\r")
}
