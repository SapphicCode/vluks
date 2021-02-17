package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"

	"github.com/hashicorp/vault/api"
	"github.com/spf13/viper"
)

func backendReadHeader(device string) (map[string]interface{}, error) {
	// open device file
	file, err := os.Open(device)
	if err != nil {
		return nil, err
	}

	// seek into header
	file.Seek(0x1000, io.SeekStart)

	// read JSON
	header := make(map[string]interface{})
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&header)
	if err != nil {
		return header, err
	}

	return header, nil
}

func backendCreateKeyfile(device, filePath string, vault *api.Logical) (string, error) {
	// read header
	header, err := backendReadHeader(device)
	if err != nil {
		return "", err
	}

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
		return "", errors.New("vluks: no available token in header")
	}

	// decrypt ciphertext
	vaultMount := viper.GetString("vault.mount")
	vaultKey := viper.GetString("vault.key")
	secret, err := vault.Write(fmt.Sprintf("%s/decrypt/%s", vaultMount, vaultKey), map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return "", err
	}
	base64KeyData := secret.Data["plaintext"].(string)
	keyData, err := base64.StdEncoding.DecodeString(base64KeyData)
	if err != nil {
		return "", err
	}

	// create keyfile
	var file *os.File
	if filePath == "" {
		file, err = ioutil.TempFile("", "vluks")
		if err != nil {
			return "", err
		}
	} else {
		err = os.MkdirAll(path.Dir(filePath), 0700)
		if err != nil {
			return "", err
		}
		file, err = os.OpenFile(filePath, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
		if err != nil {
			return "", err
		}
	}

	// write keyfile
	_, err = file.Write(keyData)
	if err != nil {
		return "", err
	}

	// close keyfile
	if err = file.Close(); err != nil {
		return "", err
	}

	return file.Name(), nil
}
