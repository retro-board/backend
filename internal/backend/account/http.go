package account

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Nerzal/gocloak/v10/pkg/jwx"
	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/retro-board/backend/internal/backend/company"
	"github.com/retro-board/backend/internal/libraries/keycloak"
)

func (a Account) callbackCookie(w http.ResponseWriter, r *http.Request, name, v string) {
	cookie := http.Cookie{
		Name:   fmt.Sprintf("retro_%s", name),
		Value:  v,
		MaxAge: int(time.Hour.Seconds()),
		Secure: r.TLS != nil,
	}
	http.SetCookie(w, &cookie)
}

//nolint:gocyclo
func (a *Account) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	st, err := r.Cookie("retro_state")
	if err != nil {
		accountError(w, errors.New("cookie: "+err.Error()))
		return
	}

	if r.URL.Query().Get("state") != st.Value {
		accountError(w, errors.New("state did not match"))
		return
	}

	oauth2Token, err := a.OAuthConfig.Exchange(a.CTX, r.URL.Query().Get("code"))
	if err != nil {
		accountError(w, errors.New("failed to exchange token: "+err.Error()))
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		accountError(w, errors.New("no id_token field in oauth2 token"))
		return
	}
	idToken, err := a.Verifier.Verify(a.CTX, rawIDToken)
	if err != nil {
		accountError(w, errors.New("Failed to verify ID Token: "+err.Error()))
		return
	}

	nonce, err := r.Cookie("retro_nonce")
	if err != nil {
		accountError(w, errors.New("nonce not found"))
		return
	}
	if idToken.Nonce != nonce.Value {
		accountError(w, errors.New("nonce did not match"))
		return
	}

	clm := jwx.Claims{}
	if err := idToken.Claims(&clm); err != nil {
		accountError(w, errors.New("Failed to parse claims: "+err.Error()))
		return
	}

	if err := a.GetRole(w, r, clm); err != nil {
		accountError(w, errors.New("Failed to get role: "+err.Error()))
		return
	}

	exists, err := a.CheckDomain(getDomain(clm.Email))
	if err != nil {
		accountError(w, errors.New("Failed to check domain: "+err.Error()))
		return
	}
	c := company.NewBlankCompany(a.Config)
	c.CompanyData.Domain = getDomain(clm.Email)
	c.SetCompanyCookie(w, r, "company")

	if exists {
		ci, err := a.CompanyInfo(w, r, getDomain(clm.Email))
		if err != nil {
			accountError(w, errors.New("Failed to get company info: "+err.Error()))
			return
		}
		if ci.Enabled {
			http.Redirect(w, r,
				fmt.Sprintf("%s://%s.%s/user/callback",
					a.Config.FrontendProto,
					ci.SubDomain,
					a.Config.Frontend,
				),
				http.StatusFound)
			return
		}
	}

	http.Redirect(w, r,
		fmt.Sprintf("%s://%s/user/callback",
			a.Config.FrontendProto,
			a.Config.Frontend,
		),
		http.StatusFound)
}

func (a *Account) GetRole(w http.ResponseWriter, r *http.Request, clm jwx.Claims) error {
	kc := keycloak.CreateKeycloak(
		r.Context(),
		a.Config.Keycloak.ClientID,
		a.Config.Keycloak.ClientSecret,
		a.Config.Keycloak.Username,
		a.Config.Keycloak.Password,
		a.Config.Keycloak.Hostname,
		a.Config.Keycloak.RealmName,
	)

	ua := UserAccount{
		ID:   clm.Subject,
		Role: a.Config.Keycloak.KeycloakRoles.SprintUser,
		Name: clm.Name,
	}

	roles, err := kc.GetUserRoles(ua.ID)
	if err != nil {
		return err
	}
	if len(roles) > 0 {
		for _, role := range roles {
			switch *role.Name {
			case a.Config.Keycloak.KeycloakRoles.CompanyOwner:
				ua.Role = a.Config.Keycloak.KeycloakRoles.CompanyOwner
				a.UserAccount = ua

			case a.Config.Keycloak.KeycloakRoles.SprintLeader:
				ua.Role = a.Config.Keycloak.KeycloakRoles.SprintLeader
				a.UserAccount = ua

			case a.Config.Keycloak.KeycloakRoles.SprintUser:
				ua.Role = a.Config.Keycloak.KeycloakRoles.SprintUser
				a.UserAccount = ua
			}
		}
	}

	exists, err := a.CheckDomain(getDomain(clm.Email))
	if err != nil {
		return err
	}
	if !exists {
		if err := kc.SetUserOwner(clm.Subject, ua.Role); err != nil {
			accountError(w, errors.New("Failed to set user owner: "+err.Error()))
			return err
		}
		ua.Role = a.Config.Keycloak.KeycloakRoles.CompanyOwner
		a.UserAccount = ua
	}

	a.UserAccount = ua
	a.frontendCookie(w, r, "user", ua)

	return nil
}

func (a *Account) CompanyInfo(w http.ResponseWriter, r *http.Request, domain string) (company.CompanyData, error) {
	c := company.NewBlankCompany(a.Config)
	c.CompanyData.Domain = domain
	if err := c.GetCompanyData(); err != nil {
		return company.CompanyData{}, err
	}

	c.SetCompanyCookie(w, r, "company")
	return c.CompanyData, nil
}

func (a *Account) LoginHandler(w http.ResponseWriter, r *http.Request) {
	nonce, err := randString(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	a.callbackCookie(w, r, "state", a.State)
	a.callbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, a.OAuthConfig.AuthCodeURL(a.State, oidc.Nonce(nonce)), http.StatusFound)
}

func accountError(w http.ResponseWriter, err error) {
	bugLog.Info(err)

	http.Error(w, err.Error(), http.StatusInternalServerError)
}

func (a Account) frontendCookie(w http.ResponseWriter, r *http.Request, name string, ua UserAccount) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, ua)
	ss, err := t.SignedString([]byte(a.Config.Local.JWTSecret))
	if err != nil {
		bugLog.Infof("failed generate token: %+v", err)
		return
	}

	cookie := http.Cookie{
		Path:     "/",
		Domain:   a.Config.Frontend,
		Name:     fmt.Sprintf("retro_%s", name),
		Value:    ss,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: false,
		Expires:  time.Now().Add(time.Hour * 1),
	}

	http.SetCookie(w, &cookie)
}