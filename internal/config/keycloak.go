package config

import (
	"errors"

	"github.com/caarlos0/env/v6"
)

type Keycloak struct {
	ClientID     string
	ClientSecret string

	Username string
	Password string

	Hostname           string `env:"KEYCLOAK_ADDRESS" envDefault:"https://keycloak.chewedfeed.com"`
	RealmName          string `env:"KEYCLOAK_REALM" envDefault:"retro-board"`
	CallbackDomainPath string `env:"KEYCLOAK_CALLBACK_DOMAIN_PATH" envDefault:"https://api.retro-board.it/account/callback"`
}

func buildKeycloak(c *Config) error {
	kc := &Keycloak{}

	if err := env.Parse(kc); err != nil {
		return err
	}

	// Client
	clientID, clientSecret, err := getKeycloakUsernamePassword(c, "kv/data/retro-board/backend-api")
	if err != nil {
		return err
	}
	kc.ClientID = clientID
	kc.ClientSecret = clientSecret

	// Account
	// username, password, err := getKeycloakUsernamePassword(c, "kv/data/retro-board/keycloak")
	// if err != nil {
	// 	return err
	// }
	// kc.Username = username
	// kc.Password = password

	c.Keycloak = *kc

	return nil
}

func getKeycloakUsernamePassword(c *Config, path string) (string, string, error) {
	var username, password string

	dets, err := c.getVaultSecrets(path)
	if err != nil {
		return username, password, err
	}

	if dets == nil {
		return username, password, errors.New("keycloak secrets not found")
	}

	secrets, err := ParseKVSecrets(dets)
	if err != nil {
		return username, password, err
	}

	if len(secrets) >= 1 {
		for _, i := range secrets {
			switch i.Key {
			case "username":
				username = i.Value
			case "password":
				password = i.Value
			}
		}
	}

	return username, password, nil
}
