package config

import (
	"errors"

	"github.com/caarlos0/env/v6"
)

type Keycloak struct {
	Username string
	Password string

	Hostname           string `env:"KEYCLOAK_ADDRESS" envDefault:"keycloak.chewedfeed.com"`
	RealmName          string `env:"KEYCLOAK_REALM" envDefault:"retro-board"`
	CallbackDomainPath string `env:"KEYCLOAK_CALLBACK_DOMAIN_PATH" envDefault:"http://localhost:3001/account/callback"`
}

func buildKeycloak(c *Config) error {
	kc := &Keycloak{}

	if err := env.Parse(kc); err != nil {
		return err
	}

	dets, err := c.getVaultSecrets("kv/data/retro-board/backend-api")
	if err != nil {
		return err
	}

	if dets == nil {
		return errors.New("keycloak secrets not found")
	}

	secrets, err := ParseKVSecrets(dets)
	if err != nil {
		return err
	}

	if len(secrets) >= 1 {
		for _, i := range secrets {
			switch i.Key {
			case "username":
				kc.Username = i.Value
			case "password":
				kc.Password = i.Value
			}
		}
	}

	c.Keycloak = *kc

	return nil
}
