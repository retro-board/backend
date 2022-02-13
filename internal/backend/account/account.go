package account

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v10"
	"github.com/Nerzal/gocloak/v10/pkg/jwx"
	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/retro-board/backend/internal/config"
	"golang.org/x/oauth2"
)

type Account struct {
	Config      *config.Config
	Verifier    *oidc.IDTokenVerifier
	OAuthConfig *oauth2.Config
	CTX         context.Context
	State       string

	UserAccount
}

type UserAccount struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Role   string `json:"role"`
}

func NewAccount(config *config.Config) *Account {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("%s/auth/realms/%s", config.Keycloak.Hostname, config.Keycloak.RealmName))
	if err != nil {
		bugLog.Infof("provider failed: %+v", err)
		return nil
	}
	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.Keycloak.ClientID,
	})
	oauthConfig := oauth2.Config{
		ClientID:     config.Keycloak.ClientID,
		ClientSecret: config.Keycloak.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  config.Keycloak.CallbackDomainPath,
		Scopes: []string{
			oidc.ScopeOpenID,
			"profile",
			"email",
		},
	}

	st, err := randString(32)
	if err != nil {
		bugLog.Infof("failed generate state: %+v", err)
		return nil
	}

	return &Account{
		Config:      config,
		Verifier:    verifier,
		OAuthConfig: &oauthConfig,
		CTX:         ctx,
		State:       st,
	}
}

func (a *Account) RegisterHandler(w http.ResponseWriter, r *http.Request) {

}

func (a *Account) getClientAndToken() (gocloak.GoCloak, *gocloak.JWT, error) {
	client := gocloak.NewClient(a.Config.Keycloak.Hostname)
	token, err := client.GetToken(a.CTX, a.Config.Keycloak.RealmName, gocloak.TokenOptions{
		ClientID:     gocloak.StringP(a.Config.Keycloak.ClientID),
		ClientSecret: gocloak.StringP(a.Config.Keycloak.ClientSecret),
		GrantType:    gocloak.StringP("password"),
		Username:     &a.Config.Keycloak.Username,
		Password:     &a.Config.Keycloak.Password,
	})
	if err != nil {
		return nil, nil, err
	}

	return client, token, nil
}

func randString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func callbackCookie(w http.ResponseWriter, r *http.Request, name, v string) {
	cookie := http.Cookie{
		Name:     fmt.Sprintf("retro_%s", name),
		Value:    v,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
}

func (a Account) frontendCookie(w http.ResponseWriter, r *http.Request, name string, ua UserAccount) {
	uas, err := json.Marshal(ua)
	if err != nil {
		bugLog.Infof("failed to marshal user account: %+v", err)
		return
	}

	cookie := http.Cookie{
		Path:     "/",
		Domain:   fmt.Sprintf("%s://%s/", a.Config.FrontendProto, a.Config.Frontend),
		Name:     fmt.Sprintf("retro_%s", name),
		Value:    html.EscapeString(string(uas)),
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: false,
		Expires:  time.Now().Add(time.Hour * 1),
	}

	http.SetCookie(w, &cookie)
}

func (a *Account) LoginHandler(w http.ResponseWriter, r *http.Request) {
	nonce, err := randString(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackCookie(w, r, "state", a.State)
	callbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, a.OAuthConfig.AuthCodeURL(a.State, oidc.Nonce(nonce)), http.StatusFound)
}

func accountError(w http.ResponseWriter, r *http.Request, err error) {
	bugLog.Info(err)

	http.Error(w, err.Error(), http.StatusInternalServerError)
}

//nolint:gocyclo
func (a *Account) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	st, err := r.Cookie("retro_state")
	if err != nil {
		accountError(w, r, err)
		return
	}

	if r.URL.Query().Get("state") != st.Value {
		accountError(w, r, errors.New("state did not match"))
		return
	}

	oauth2Token, err := a.OAuthConfig.Exchange(a.CTX, r.URL.Query().Get("code"))
	if err != nil {
		accountError(w, r, errors.New("Failed to exchange token: "+err.Error()))
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		accountError(w, r, errors.New("No id_token field in oauth2 token."))
		return
	}
	idToken, err := a.Verifier.Verify(a.CTX, rawIDToken)
	if err != nil {
		accountError(w, r, errors.New("Failed to verify ID Token: "+err.Error()))
		return
	}

	nonce, err := r.Cookie("retro_nonce")
	if err != nil {
		accountError(w, r, errors.New("nonce not found"))
		return
	}
	if idToken.Nonce != nonce.Value {
		accountError(w, r, errors.New("nonce did not match"))
		return
	}

	clm := jwx.Claims{}
	if err := idToken.Claims(&clm); err != nil {
		accountError(w, r, errors.New("Failed to parse claims: "+err.Error()))
		return
	}

	if err := a.GetRole(w, r, clm); err != nil {
		accountError(w, r, errors.New("Failed to get role: "+err.Error()))
		return
	}

	http.Redirect(w, r,
		fmt.Sprintf("%s://%s/user/callback",
			a.Config.FrontendProto,
			a.Config.Frontend,
		),
		http.StatusFound)
}

func (a *Account) CheckDomain(domain string) (bool, error) {
	return false, nil
}

func (a *Account) GetRole(w http.ResponseWriter, r *http.Request, clm jwx.Claims) error {
	domainParts := strings.Split(clm.Email, "@")
	fullDomain := domainParts[len(domainParts)-1]
	domain := strings.Split(fullDomain, ".")[0]
	exists, err := a.CheckDomain(domain)
	if err != nil {
		return err
	}

	ua := UserAccount{
		ID:     clm.Subject,
		Role:   a.Config.Keycloak.KeycloakRoles.SprintUser,
		Domain: domain,
		Name:   clm.Name,
	}

	if !exists {
		if err := a.setUserOwner(clm.Subject); err != nil {
			accountError(w, r, errors.New("Failed to set user owner: "+err.Error()))
			return err
		}
		ua.Role = a.Config.Keycloak.KeycloakRoles.CompanyOwner
		a.UserAccount = ua
	}

	a.UserAccount = ua
	a.frontendCookie(w, r, "user", ua)
	return nil
}

func (a *Account) setUserOwner(userId string) error {
	client, token, err := a.getClientAndToken()
	if err != nil {
		return err
	}

	roles, err := client.GetRealmRoles(a.CTX, token.AccessToken, a.Config.Keycloak.RealmName, gocloak.GetRoleParams{
		Search: gocloak.StringP(a.Config.Keycloak.CompanyOwner),
	})
	if err != nil {
		return err
	}

	if err := client.AddRealmRoleToUser(a.CTX, token.AccessToken, a.Config.Keycloak.RealmName, userId, []gocloak.Role{{
		ID:          roles[0].ID,
		Name:        roles[0].Name,
		ContainerID: roles[0].ContainerID,
	}}); err != nil {
		return err
	}

	return nil
}

// func (a *Account) CheckUserPermission(userId, permissionName string) (bool, error) {
// 	client, token, err := a.getClientAndToken()
// 	if err != nil {
// 		return false, err
// 	}
//
// 	client.
//
// 	return false, nil
// }
