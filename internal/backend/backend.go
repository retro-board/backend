package backend

import (
	"context"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"golang.org/x/oauth2"

	"github.com/retro-board/backend/internal/config"
)

type Backend struct {
	Config *config.Config
}

func (b Backend) Start() error {
	oc := oauth2.Config{
		ClientID: "retro-board",
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://keycloak.retro-board.com/auth/realms/retro-board/protocol/openid-connect/token",
		},
	}

	ctx := context.Background()
	token, err := oc.PasswordCredentialsToken(ctx, b.Config.Keycloak.Username, b.Config.Keycloak.Password)
	if err != nil {
		return err
	}

	bugLog.Local().Infof("Token: %+v", token)

	return nil
}
