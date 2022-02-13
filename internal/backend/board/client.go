package board

import (
	"encoding/json"
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/go-chi/chi/v5"
)

type ClientRequest struct {
	BoardID string `json:"board_id"`
	UserID  string `json:"user_id"`
}

// TODO: add error handling
//nolint:deadcode,unused
func jsonError(w http.ResponseWriter, msg string, errs error) {
	bugLog.Local().Info("jsonError: %+v", errs)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{
		Error: msg,
	}); err != nil {
		bugLog.Local().Debugf("jsonError: %+v", err)
	}
}

func (b *Board) SetupClientHandler(w http.ResponseWriter, r *http.Request) {
	boardID := chi.URLParam(r, "boardID")

	bugLog.Infof("BoardID: %+v", boardID)
}
