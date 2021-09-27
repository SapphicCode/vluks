package main

import (
	_ "embed"
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

//go:embed LICENSE.md
var license string

var licenseCommand = &cobra.Command{
	Use:   "license",
	Short: "Prints the license under which this program may be distributed",

	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(license)
	},
}
