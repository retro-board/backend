package board

import (
	"context"

	"github.com/retro-board/backend/internal/config"
	"github.com/retro-board/backend/internal/libraries/keycloak"
)

type Board struct {
	CTX context.Context

	Config *config.Config
}

type BoardInfo struct {
	ID              int    `json:"id"`
	Name            string `json:"name"`
	LinkName        string `json:"link_name"`
	RetrosCompleted int    `json:"retros_completed"`
	TeamScore       int    `json:"team_score"`
	PreviousScore   int    `json:"previous_score"`
}

func NewBoard(config *config.Config) *Board {
	return &Board{
		Config: config,
	}
}

func (b *Board) GetAll(subDomain, userID string) ([]BoardInfo, error) {
	kc := keycloak.CreateKeycloak(
		b.CTX,
		b.Config.Keycloak.ClientID,
		b.Config.Keycloak.ClientSecret,
		b.Config.Keycloak.IDofClient,
		b.Config.Keycloak.Username,
		b.Config.Keycloak.Password,
		b.Config.Keycloak.Hostname,
		b.Config.Keycloak.RealmName,

		keycloak.KeycloakRoles{
			User:   b.Config.Keycloak.KeycloakRoles.SprintUser,
			Leader: b.Config.Keycloak.KeycloakRoles.SprintLeader,
			Owner:  b.Config.Keycloak.KeycloakRoles.CompanyOwner,
		})
	userRole, err := kc.GetUserRole(userID)
	if err != nil {
		return nil, err
	}

	if allowed, err := kc.IsAllowed(userID, userRole, "board:list"); err != nil {
		return nil, err
	} else if !allowed {
		return nil, nil
	}

	boards, err := b.GetAllBoards(subDomain)
	if err != nil {
		return nil, err
	}

	return boards, nil
}
