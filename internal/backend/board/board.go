package board

import (
	"net/http"

	"github.com/retro-board/backend/internal/config"
)

type Board struct {
	Config *config.Config
}

func NewBoard(config *config.Config) *Board {
	return &Board{
		Config: config,
	}
}

func (b Board) GetHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Hello World"))
}
