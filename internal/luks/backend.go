package luks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Backend provides a backend to LUKS v2 and cryptsetup
type Backend struct {
	Logger zerolog.Logger
	Vault  *api.Client
}

// ReadHeader returns a map of the LUKS v2 JSON header
// Useful for parsing the tokens, keyfiles, etc
func (be *Backend) ReadHeader(device string) map[string]interface{} {
	logger := be.Logger.With().Str("device", device).Logger()

	// open device file
	file, err := os.Open(device)
	if err != nil {
		return nil
	}
	logger.Debug().Msg("Device opened.")

	// seek into header
	file.Seek(0x1000, io.SeekStart)
	logger.Debug().Msg("Seeked into header.")

	// read JSON
	header := make(map[string]interface{})
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&header)
	if err != nil {
		be.Logger.Fatal().Err(err).Msg("Error reading JSON header.")
		return nil
	}
	logger.Debug().Interface("header", header).Msg("Header successfully read.")

	return header
}

// CreateKeyfile creates a Vault-encrypted LUKS keyfile and adds it to LUKS
// This function uses cryptsetup and requires user interaction
// Returns the keyfile path, clean up is left to the caller
func (be *Backend) CreateKeyfile(device, filePath string) string {
	logger := be.Logger.With().Str("device", device).Logger()

	// read header
	header := be.ReadHeader(device)

	// read tokens
	tokens := header["tokens"].(map[string]interface{})
	var ciphertext string
	for _, tokenInterface := range tokens {
		token := tokenInterface.(map[string]interface{})
		if token["type"] != "vluks" {
			continue
		}
		ciphertext = token["ciphertext"].(string)
	}
	if ciphertext == "" {
		logger.Fatal().Msg("No available token found in header.")
	}

	// decrypt ciphertext
	vaultMount := viper.GetString("vault.mount")
	vaultKey := viper.GetString("vault.key")
	secret, err := be.Vault.Logical().Write(fmt.Sprintf("%s/decrypt/%s", vaultMount, vaultKey), map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		logger.Fatal().Err(err).Msg("Vault could not decode ciphertext.")
	}
	base64KeyData := secret.Data["plaintext"].(string)
	keyData, err := base64.StdEncoding.DecodeString(base64KeyData)
	if err != nil {
		logger.Panic().Err(err).Msg("Error decoding Vault base64?")
	}

	// create keyfile
	var file *os.File
	if filePath == "" {
		file, err = ioutil.TempFile("", "vluks")
		if err != nil {
			logger.Fatal().Err(err).Msg("Error creating temporary keyfile.")
		}
	} else {
		logger := logger.With().Str("keyfilePath", filePath).Logger()
		err = os.MkdirAll(path.Dir(filePath), 0700)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error creating path for keyfile.")
		}
		file, err = os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error opening custom keyfile.")
		}
	}

	// write keyfile
	_, err = file.Write(keyData)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error writing keyfile.")
	}

	// close keyfile
	if err = file.Close(); err != nil {
		logger.Panic().Err(err).Msg("Error closing keyfile?")
	}

	return file.Name()
}
