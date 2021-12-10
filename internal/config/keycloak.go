package config

import (
  "errors"
)

type Keycloak struct {
	Username string
	Password string
}

func buildKeycloak(c *Config) error {
	kc := &Keycloak{}

	dets, err := c.getVaultSecrets("kv/data/retro-board/keycloak")
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
