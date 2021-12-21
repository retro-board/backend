package company

import (
	"encoding/json"
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
)

type CreateRequest struct {
	Name string `json:"name"`
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

func (c *Company) CreateHandler(w http.ResponseWriter, r *http.Request) {
	var cr CreateRequest

	if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
		jsonError(w, "Invalid request payload", err)
		return
	}

	if err := c.CreateCompany(cr.Name); err != nil {
		jsonError(w, "Failed to create company", err)
		return
	}

	sc := struct {
		Status string `json:"status"`
	}{
		Status: "Company created successfully",
	}

	if err := json.NewEncoder(w).Encode(sc); err != nil {
		jsonError(w, "Failed to encode response", err)
		return
	}
	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
}
