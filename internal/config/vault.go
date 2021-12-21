package config

import (
	"fmt"

	"github.com/caarlos0/env/v6"
	vaultAPI "github.com/hashicorp/vault/api"
)

type Vault struct {
	Address string `env:"VAULT_ADDRESS" envDefault:"http://vault.vault:8200"`
	Token   string `env:"VAULT_TOKEN" envDefault:""`
}

type KVSecret struct {
	Key   string
	Value string
}

type KVSecretData struct {
	Data map[string]interface{} `json:"data"`
}

func GetVaultSecrets(vaultAddress, vaultToken, secretPath string) (map[string]interface{}, error) {
	var m = make(map[string]interface{})

	cfg := vaultAPI.DefaultConfig()
	cfg.Address = vaultAddress
	client, err := vaultAPI.NewClient(cfg)
	if err != nil {
		return m, err
	}

	client.SetToken(vaultToken)

	data, err := client.Logical().Read(secretPath)
	if err != nil {
		return m, err
	}

	if data == nil {
		return m, fmt.Errorf("no data at path: %s", secretPath)
	}

	return data.Data, nil
}

func (c *Config) getVaultSecrets(secretPath string) (map[string]interface{}, error) {
	return GetVaultSecrets(c.Vault.Address, c.Vault.Token, secretPath)
}

func buildVault(c *Config) error {
	v := &Vault{}

	if err := env.Parse(v); err != nil {
		return err
	}

	c.Vault = *v

	return nil
}

func ParseKVSecrets(data map[string]interface{}) ([]KVSecret, error) {
	var secrets []KVSecret

	for ik, iv := range data {
		if ik == "data" {
			for k, v := range iv.(map[string]interface{}) {
				secrets = append(secrets, KVSecret{
					Key:   k,
					Value: fmt.Sprintf("%v", v),
				})
			}
		}
	}

	return secrets, nil
}
