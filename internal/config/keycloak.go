package config

import (
	"context"
	"errors"

	"github.com/Nerzal/gocloak/v10"
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
	clientID, clientSecret, err := getKeycloakUsernamePassword(c, "kv/data/retro-board/backend-api")
	if err != nil {
		return err
	}
	kc.ClientID = clientID
	kc.ClientSecret = clientSecret

	// Account
	username, password, err := getKeycloakUsernamePassword(c, "kv/data/retro-board/api-account")
	if err != nil {
		return err
	}
	kc.Username = username
	kc.Password = password

	// ID of client
	id, err := getIDofClient(kc)
	if err != nil {
		return err
	}
	kc.IDofClient = id

	c.Keycloak = *kc

	return nil
}

func getIDofClient(k *Keycloak) (string, error) {
	ctx := context.Background()

	client := gocloak.NewClient(k.Hostname)
	token, err := client.GetToken(ctx, k.RealmName, gocloak.TokenOptions{
		ClientID:     gocloak.StringP(k.ClientID),
		ClientSecret: gocloak.StringP(k.ClientSecret),
		GrantType:    gocloak.StringP("password"),
		Username:     &k.Username,
		Password:     &k.Password,
	})
	if err != nil {
		return "", err
	}

	clients, err := client.GetClients(ctx, token.AccessToken, k.RealmName, gocloak.GetClientsParams{
		ClientID: gocloak.StringP(k.ClientID),
	})
	if err != nil {
		return "", err
	}

	return *clients[0].ID, nil
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
