package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func initConfig() error {
	viper.SetConfigName("vluks")
	viper.SetConfigType("yaml")

	viper.AddConfigPath("$HOME/.config/vluks/")
	viper.AddConfigPath("$HOME/.config/")
	viper.AddConfigPath("/etc/vluks/")
	viper.AddConfigPath("/etc/")

	// defaults loaded via Vault: vault.address, vault.token
	viper.SetDefault("vault.mount", "transit")
	viper.SetDefault("vault.key", "luks")

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()
	return viper.ReadInConfig()
}

func getLogger(cmd *cobra.Command) (logger zerolog.Logger) {
	if value, _ := cmd.Flags().GetBool("json"); value {
		logger = zerolog.New(os.Stdout)
	} else {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout})
	}
	logger = logger.With().Timestamp().Logger().Level(zerolog.InfoLevel)

	return
}

func getVault() (vault *api.Client, err error) {
	vault, err = api.NewClient(api.DefaultConfig())
	if err != nil {
		return
	}

	// get address
	if address := viper.GetString("vault.address"); address != "" {
		vault.SetAddress(address)
	}
	if token := viper.GetString("vault.token"); token != "" {
		vault.SetToken(token)
	}

	// TODO AppRole login, since we want this baked in as tightly as possible for initramfs
	return
}

func main() {
	// initialize config
	initConfig()

	root := &cobra.Command{Use: "vluks", Short: "A Vault-based LUKS encryption mechanism"}
	root.PersistentFlags().Bool("json", false, "Enable JSON logging")
	root.PersistentFlags().BoolP("debug", "v", false, "Enable debug logging")

	root.AddCommand(addKey())

	if err := root.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
