package config

import (
	"errors"

	"github.com/caarlos0/env/v6"
)

type KeycloakRoles struct {
	CompanyOwner string `env:"OWNER_ROLE" envDefault:"company-owner"`
	SprintLeader string `env:"LEADER_ROLE" envDefault:"sprint-leader"`
	SprintUser   string `env:"USER_ROLE" envDefault:"sprint-user"`
}

type Keycloak struct {
	ClientID     string
	ClientSecret string
	IDofClient   string

	Username string `env:"KEYCLOAK_API_USER"`
	Password string `env:"KEYCLOAK_API_PASSWORD"`

	Hostname           string `env:"KEYCLOAK_ADDRESS" envDefault:"https://keycloak.chewedfeed.com"`
	RealmName          string `env:"KEYCLOAK_REALM" envDefault:"retro-board"`
	CallbackDomainPath string `env:"KEYCLOAK_CALLBACK_DOMAIN_PATH" envDefault:"https://backend.retro-board.it/account/callback"`

	KeycloakRoles
}

func buildKeycloak(c *Config) error {
	kc := &Keycloak{}

	if err := env.Parse(kc); err != nil {
		return err
	}

	// Client
	client, err := getKeycloakSecretsFromVault(c, "kv/data/retro-board/backend-api")
	if err != nil {
		return err
	}

	kc.ClientID = client["username"]
	kc.ClientSecret = client["password"]
	kc.IDofClient = client["id"]

	// Account
	account, err := getKeycloakSecretsFromVault(c, "kv/data/retro-board/api-account")
	if err != nil {
		return err
	}
	kc.Username = account["username"]
	kc.Password = account["password"]

	c.Keycloak = *kc

	return nil
}

func getKeycloakSecretsFromVault(c *Config, path string) (map[string]string, error) {
	dets, err := c.getVaultSecrets(path)
	if err != nil {
		return nil, err
	}

	if dets == nil {
		return nil, errors.New("no secrets found")
	}

	kvs, err := ParseKVSecrets(dets)
	if err != nil {
		return nil, err
	}

	results := make(map[string]string)
	if len(kvs) == 0 {
		return nil, errors.New("no secrets found")
	}

	for _, kv := range kvs {
		results[kv.Key] = kv.Value
	}

	return results, nil
}
