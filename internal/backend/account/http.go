package account

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Nerzal/gocloak/v11/pkg/jwx"
	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/retro-board/backend/internal/backend/company"
	"github.com/retro-board/backend/internal/libraries/encrypt"
	"github.com/retro-board/backend/internal/libraries/keycloak"
)

func (a Account) callbackCookie(w http.ResponseWriter, r *http.Request, name, v string) {
	http.SetCookie(w, &http.Cookie{
		Name:   fmt.Sprintf("retro_%s", name),
		Value:  v,
		MaxAge: int(time.Hour.Seconds()),
		Secure: r.TLS != nil,
		Domain: r.Host,
	})
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
	c.CTX = r.Context()
	c.CompanyData.Domain = getDomain(clm.Email)
	c.SetCompanyCookie(w, r, "company")

	if exists {
		ci, err := a.CompanyInfo(w, r, getDomain(clm.Email))
		if err != nil {
			accountError(w, errors.New("Failed to get company info: "+err.Error()))
			return
		}

		a.SetUserCookie(w, r, "user", ci.SubDomain, a.UserAccount)

		if ci.Enabled && !c.Config.Local.Development {
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
		a.Config.Keycloak.IDofClient,
		a.Config.Keycloak.Username,
		a.Config.Keycloak.Password,
		a.Config.Keycloak.Hostname,
		a.Config.Keycloak.RealmName,

		keycloak.KeycloakRoles{
			User:   a.Config.Keycloak.KeycloakRoles.SprintUser,
			Leader: a.Config.Keycloak.KeycloakRoles.SprintLeader,
			Owner:  a.Config.Keycloak.KeycloakRoles.CompanyOwner,
		},
	)

	ua := UserAccount{
		ID:         clm.Subject,
		OriginalID: clm.Subject,
		Role:       a.Config.Keycloak.KeycloakRoles.SprintUser,
		Name:       clm.Name,
		Perms:      []string{},
	}

	userid, err := encrypt.NewEncrypt(a.Config.Local.TokenSeed).Encrypt(ua.ID)
	if err != nil {
		return err
	}
	ua.ID = userid

	exists, err := a.CheckDomain(getDomain(clm.Email))
	if err != nil {
		return err
	}
	if !exists {
		if err := kc.SetUserOwner(clm.Subject); err != nil {
			accountError(w, errors.New("Failed to set user owner: "+err.Error()))
			return err
		}
		ua.Role = a.Config.Keycloak.KeycloakRoles.CompanyOwner
	} else {
		role, err := kc.GetUserRole(clm.Subject)
		if err != nil {
			accountError(w, errors.New("failed to get user role: "+err.Error()))
			return err
		}
		ua.Role = role
	}

	userPerms, err := a.GetUserPerms(ua.OriginalID)
	if err != nil {
		return err
	}
	ua.Perms = userPerms

	a.UserAccount = ua
	a.SetUserCookie(w, r, "user", "", ua)

	return nil
}

func (a *Account) CompanyInfo(w http.ResponseWriter, r *http.Request, domain string) (company.CompanyData, error) {
	c := company.NewBlankCompany(a.Config)
	c.CompanyData.Domain = domain
	c.CTX = r.Context()
	if err := c.GetCompanyData(); err != nil {
		return company.CompanyData{}, err
	}

	// bugLog.Logf("got company data: %+v", c.CompanyData)

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

func (a Account) SetUserCookie(w http.ResponseWriter, r *http.Request, name, subDomain string, ua UserAccount) {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, ua)
	ss, err := t.SignedString([]byte(a.Config.Local.JWTSecret))
	if err != nil {
		bugLog.Infof("failed generate token: %+v", err)
		return
	}

	cookieDomain := a.Config.Frontend
	if subDomain != "" && !a.Config.Development {
		cookieDomain = fmt.Sprintf("%s.%s", subDomain, a.Config.Frontend)
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

	// bugLog.Logf("userCookie: %s, %+v", cookieDomain, cookie)

	http.SetCookie(w, &cookie)
}

func (a *Account) GetUserPerms(userID string) ([]string, error) {
	kc := keycloak.CreateKeycloak(
		a.CTX,
		a.Config.Keycloak.ClientID,
		a.Config.Keycloak.ClientSecret,
		a.Config.Keycloak.IDofClient,
		a.Config.Keycloak.Username,
		a.Config.Keycloak.Password,
		a.Config.Keycloak.Hostname,
		a.Config.Keycloak.RealmName,
		keycloak.KeycloakRoles{})
	perms, err := kc.GetAllUserScopes(userID)
	if err != nil {
		return []string{}, nil
	}

	return perms, nil
}
