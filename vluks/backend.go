package vluks

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/spf13/viper"
)

// Backend provides a backend to LUKSv2 operations and Vault
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

// ReadCrypttab parses /etc/crypttab.
// Returns a list of potential keyfile=none devices.
func (be *Backend) ReadCrypttab(crypttab string) []string {
	logger := be.Logger.With().Str("module", "crypttab").Str("crypttab", crypttab).Logger()

	data, err := ioutil.ReadFile(crypttab)
	if err != nil {
		logger.Fatal().Err(err).Msg("Unable to read crypttab.")
	}

	devices := parseCrypttab(string(data))

	// we have a device map, now what? well...
	systemdElegibleDevices := make([]string, 0, 8)
	for _, device := range devices {
		switch device[2] {
		case "", "none":
			systemdElegibleDevices = append(systemdElegibleDevices, device[0])
		}
	}

	return systemdElegibleDevices
}

func parseCrypttab(crypttab string) [][]string {
	devices := make([][]string, 0, 8)
parser:
	for _, line := range strings.Split(crypttab, "\n") {
		line := strings.TrimSpace(line)
		if line == "" {
			continue parser
		}

		device := make([]string, 4)
		field := 0
		readingWhitespace := false
		for _, char := range line {
			// ignore comments
			if char == '#' {
				continue parser
			}
			// find out if we're reading whitespace
			if char == ' ' || char == '\t' {
				// if this is our first encountered whitespace, shift the field (up to 4)
				if !readingWhitespace && field < 3 {
					field++
				}
				readingWhitespace = true
			} else {
				readingWhitespace = false
			}
			// if we're still not reading whitespace, append the field
			if !readingWhitespace {
				device[field] += string(char)
			}
		}
		devices = append(devices, device)
	}
	return devices
}
