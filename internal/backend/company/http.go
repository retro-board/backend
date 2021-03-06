package company

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/golang-jwt/jwt/v4"
	"github.com/retro-board/backend/internal/libraries/encrypt"
	"github.com/retro-board/backend/internal/libraries/keycloak"
)

type CreateRequest struct {
	FirstTeamName string `json:"firstTeamName"`
	CompanyName   string `json:"name"`
	SubDomain     string `json:"subDomain"`
	Domain        string `json:"domain"`
	UserRole      string `json:"userRole"`
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

// TODO: fix the complexity of this function
//nolint:gocyclo
func (c *Company) CreateHandler(w http.ResponseWriter, r *http.Request) {
	var cr CreateRequest
	c.CTX = r.Context()

	if err := json.NewDecoder(r.Body).Decode(&cr); err != nil {
		jsonError(w, "Invalid request payload", err)
		return
	}

	switch strings.ToLower(cr.SubDomain) {
	case "":
		jsonError(w, "SubDomain is required", nil)
		return
	case "www":
	case "backend":
	case "api":
	case "retro-board":
	case "blank-company":
		jsonError(w, fmt.Sprintf("SubDomain cannot be %s", cr.SubDomain), nil)
		return
	}

	c.CompanyData = CompanyData{
		Name:      cr.CompanyName,
		SubDomain: cr.SubDomain,
		Domain:    cr.Domain,
	}

	kc := keycloak.CreateKeycloak(
		r.Context(),
		c.Config.Keycloak.ClientID,
		c.Config.Keycloak.ClientSecret,
		c.Config.Keycloak.IDofClient,
		c.Config.Keycloak.Username,
		c.Config.Keycloak.Password,
		c.Config.Keycloak.Hostname,
		c.Config.Keycloak.RealmName,

		keycloak.KeycloakRoles{
			User:   c.Config.Keycloak.KeycloakRoles.SprintUser,
			Leader: c.Config.Keycloak.KeycloakRoles.SprintLeader,
			Owner:  c.Config.Keycloak.KeycloakRoles.CompanyOwner,
		},
	)

	userID, err := encrypt.NewEncrypt(c.Config.Local.TokenSeed).Decrypt(r.Header.Get("X-User-Token"))
	if err != nil {
		jsonError(w, "Invalid request payload", err)
		return
	}

	allowed, err := kc.IsAllowed(userID, cr.UserRole, "company:create")
	if err != nil {
		jsonError(w, "Invalid request payload", err)
		return
	}

	if allowed {
		if err := c.CreateCompany(cr.FirstTeamName); err != nil {
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
}

func (c *Company) SetCompanyCookie(w http.ResponseWriter, r *http.Request, name string) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, c.CompanyData)
	ss, err := t.SignedString([]byte(c.Config.Local.JWTSecret))
	if err != nil {
		bugLog.Infof("failed generate token: %+v", err)
		return
	}

	cookieDomain := c.Config.Frontend
	if c.CompanyData.SubDomain != "" && !c.Config.Development {
		if c.CompanyData.Enabled {
			http.SetCookie(w, &http.Cookie{
				Path:     "/",
				Domain:   cookieDomain,
				Name:     fmt.Sprintf("retro_%s", name),
				Value:    ss,
				MaxAge:   int(time.Hour.Seconds()),
				Secure:   r.TLS != nil,
				HttpOnly: false,
				Expires:  time.Now().Add(time.Hour * 1),
			})

			cookieDomain = fmt.Sprintf("%s.%s", c.CompanyData.SubDomain, c.Config.Frontend)
		}
	}
	cookie := http.Cookie{
		Path:     "/",
		Domain:   cookieDomain,
		Name:     fmt.Sprintf("retro_%s", name),
		Value:    ss,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: false,
		Expires:  time.Now().Add(time.Hour * 1),
	}

	// bugLog.Logf("companyCookie: %s, %+v", cookieDomain, cookie)

	http.SetCookie(w, &cookie)
}
