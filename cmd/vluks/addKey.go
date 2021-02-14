package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var keySlotCreationRegex = regexp.MustCompile(`Key slot (\d+) created\.`)

func addKey() *cobra.Command {
	return &cobra.Command{
		Use:   "add-key <device>",
		Short: "Generates a key in Vault and adds it to LUKS as a keyfile",
		Args:  cobra.ExactArgs(1),

		Run: func(command *cobra.Command, args []string) {
			device := args[0]

			logger := getLogger(command)
			vault, err := getVault()
			if err != nil {
				logger.Panic().Err(err).Msg("Unable to load Vault.")
			}

			transitMount := viper.GetString("vault.mount")
			transitKey := viper.GetString("vault.key")
			logger.Debug().Str("mount", transitMount).Str("key", transitKey).Msg("Loaded Vault key parameters.")

			// Generate key
			secret, err := vault.Logical().Write(
				fmt.Sprintf("%s/datakey/plaintext/%s", transitMount, transitKey),
				map[string]interface{}{
					"bits": 512,
				},
			)
			if err != nil {
				logger.Fatal().Err(err).Msg("Datakey generation failed.")
			}

			logger.Info().Msg("Key generated. Proceeding to add keyfile to LUKS...")

			// Write temporary keyfile
			keyData, err := base64.StdEncoding.DecodeString(secret.Data["plaintext"].(string))
			if err != nil {
				logger.Panic().Err(err).Msg("Vault plaintext undecodable?")
			}
			keyFile, err := ioutil.TempFile("", "vluks")
			defer os.Remove(keyFile.Name()) // Make sure it gets cleaned up
			_, err = keyFile.Write(keyData)
			if err != nil {
				logger.Fatal().Err(err).Msg("Unable to write temporary keyfile.")
			}
			err = keyFile.Close()
			if err != nil {
				logger.Panic().Err(err).Msg("Error closing temporary keyfile.")
			}

			// Add key to LUKS
			logger.Info().Msgf("$ cryptsetup -v luksAddKey %s %s", device, keyFile.Name())
			cryptsetup := exec.Command("cryptsetup", "-v", "luksAddKey", device, keyFile.Name())
			// Connect stdin for normal cryptsetup operation
			cryptsetup.Stdin = os.Stdin
			// Sniff the output
			var out bytes.Buffer
			cryptsetup.Stdout = io.MultiWriter(os.Stdout, &out)
			cryptsetup.Stderr = io.MultiWriter(os.Stderr, &out)
			// Run
			err = cryptsetup.Run()
			if err != nil {
				logger.Fatal().Err(err).Str("user", os.Getenv("USER")).Msg("cryptsetup didn't exit cleanly. User error.")
			}

			// Regex added key slot: "Key slot %d created."
			keySlotSubmatches := keySlotCreationRegex.FindSubmatch(out.Bytes())
			if keySlotSubmatches == nil {
				logger.Panic().Msg("Couldn't match the key slot to add a token for. Please file a bug report.")
			}
			keySlot := string(keySlotSubmatches[1])

			// Create token JSON
			logger.Debug().Str("keyslot", keySlot).Msg("Creating token JSON...")
			token := make(map[string]interface{})
			token["type"] = "vluks"
			token["keyslots"] = []string{keySlot}
			token["ciphertext"] = secret.Data["ciphertext"]

			var jsonBuffer bytes.Buffer
			err = json.NewEncoder(&jsonBuffer).Encode(token)
			if err != nil {
				logger.Panic().Err(err).Msg("Unable to encode token JSON.")
			}

			// Add token JSON to header
			logger.Info().Msg("Adding token to header...")
			logger.Info().Msgf("$ cryptsetup -v token import %s", device)
			cryptsetup = exec.Command("cryptsetup", "-v", "token", "import", device)
			cryptsetup.Stdin = &jsonBuffer
			cryptsetup.Stdout = os.Stdout
			cryptsetup.Stderr = os.Stderr
			err = cryptsetup.Run()
			if err != nil {
				logger.Fatal().Err(err).Msg("cryptsetup didn't let us add a token.")
			}
			logger.Info().Str("keyslot", keySlot).Msg("Success! Vault token added to the LUKS header.")
		},
	}
}
