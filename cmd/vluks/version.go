package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var version string
var commit string

var versionCommand = &cobra.Command{
	Use:   "version",
	Short: "Shows the compiled-in version, then exits",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("%s\n%s\n", version, commit)
	},
}
