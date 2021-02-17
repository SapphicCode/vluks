package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

func systemdCryptsetup() *cobra.Command {
	return &cobra.Command{
		Use:  "systemd-cryptsetup",
		Long: "Attempts to write keyfiles for all devices in /etc/crypttab to /run/systemd-cryptsetup.d/<volume>.key",

		Args:   cobra.NoArgs,
		Hidden: true,

		Run: func(command *cobra.Command, args []string) {
			logger := getLogger(command)
			vault, err := getVault()
			if err != nil {
				logger.Panic().Err(err).Msg("Error initializing Vault client.")
			}

			crypttabFile, err := os.Open("/etc/crypttab")
			if err != nil {
				logger.Fatal().Err(err).Msg("Unable to open crypttab.")
			}

			crypttabContents, err := ioutil.ReadAll(crypttabFile)
			if err != nil {
				logger.Fatal().Err(err).Msg("Unable to read crypttab.")
			}

			crypttabLines := strings.Split(string(crypttabContents), "\n")
			for i, line := range crypttabLines {
				logger = logger.With().Int("line", i).Logger()

				if line == "" {
					continue
				}
				lineArgs := strings.Split(line, " ")
				if len(lineArgs) < 2 {
					continue
				}

				deviceName := lineArgs[0]

				deviceFile := lineArgs[1]
				if deviceFile[0:5] == "UUID=" {
					deviceFile = fmt.Sprintf("/dev/disk/by-uuid/%s", deviceFile[5:])
				}

				var deviceKey string = "none"
				if len(lineArgs) > 2 {
					deviceKey = lineArgs[2]
				}
				if deviceKey != "none" {
					continue
				}

				// TODO: pass logger into backend functions
				keyFilePath, err := backendCreateKeyfile(
					deviceFile, fmt.Sprintf("/run/cryptsetup-keys.d/%s.key", deviceName), vault.Logical(),
				)
				if err != nil {
					logger.Error().Err(err).Str("name", deviceName).Msg("Unable to create keyfile for device.")
				} else {
					logger.Info().Str("keyfile", keyFilePath).Msg("Keyfile created for device.")
				}
			}
		},
	}
}
