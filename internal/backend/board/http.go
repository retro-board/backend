package board

import (
	"encoding/json"
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/retro-board/backend/internal/libraries/encrypt"
)

type BoardListRequest struct {
	DomainName string `json:"domain"`
	Role       string `json:"role"`
}

type ClientRequest struct {
	BoardID string `json:"board_id"`
	UserID  string `json:"user_id"`
}

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

func (b Board) GetHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = w.Write([]byte("Hello World"))
}

func (b Board) GetAllHandler(w http.ResponseWriter, r *http.Request) {
	var subdomain string = r.URL.Query().Get("subdomain")
	var role string = r.URL.Query().Get("role")
	b.CTX = r.Context()

	userToken := r.Header.Get("X-User-Token")
	userId, err := encrypt.NewEncrypt(b.Config.Local.TokenSeed).Decrypt(userToken)
	if err != nil {
		jsonError(w, "Invalid token", err)
		return
	}

	boards, err := b.GetAll(subdomain, role, userId)
	if err != nil {
		jsonError(w, "Error getting boards", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(boards); err != nil {
		jsonError(w, "Error encoding boards", err)
		return
	}
}
