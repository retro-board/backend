package board

import (
	"github.com/retro-board/backend/internal/config"
)

type Board struct {
	Config *config.Config
}

type BoardInfo struct {
	Name            string `json:"name"`
	RetrosCompleted int    `json:"retros_completed"`
	TeamScore       int    `json:"team_score"`
}

func NewBoard(config *config.Config) *Board {
	return &Board{
		Config: config,
	}
}

func (b *Board) GetAll(subDomain, roleName, userId string) ([]BoardInfo, error) {
	return []BoardInfo{
		{
			Name:            "Test",
			RetrosCompleted: 0,
			TeamScore:       -50,
		},
	}, nil
}
