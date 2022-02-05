package account

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
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
}

type UserAccount struct {
	ID     string
	Domain string
}

func NewAccount(config *config.Config) *Account {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("%s/auth/realms/%s", config.Keycloak.Hostname, config.Keycloak.RealmName))
	if err != nil {
		bugLog.Infof("provider failed: %+v", err)
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

	return &Account{
		Config:      config,
		Verifier:    verifier,
		OAuthConfig: &oauthConfig,
		CTX:         ctx,
	}
}

func (a *Account) RegisterHandler(w http.ResponseWriter, r *http.Request) {

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

func (a Account) frontendCookie(w http.ResponseWriter, r *http.Request, name string, claims jwx.Claims) {
	cookie := http.Cookie{
		Name:     fmt.Sprintf("retro_%s", name),
		Value:    "",
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}

	http.SetCookie(w, &cookie)
}

func (a *Account) LoginHandler(w http.ResponseWriter, r *http.Request) {
	st, err := randString(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	nonce, err := randString(32)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	callbackCookie(w, r, "state", st)
	callbackCookie(w, r, "nonce", nonce)

	http.Redirect(w, r, a.OAuthConfig.AuthCodeURL(st, oidc.Nonce(nonce)), http.StatusFound)
}

//nolint:gocyclo
func (a *Account) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	st, err := r.Cookie("retro_state")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if r.URL.Query().Get("state") != st.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

	oauth2Token, err := a.OAuthConfig.Exchange(a.CTX, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := a.Verifier.Verify(a.CTX, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	nonce, err := r.Cookie("retro_nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	clm := jwx.Claims{}
	if err := idToken.Claims(&clm); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	domainParts := strings.Split(clm.Email, "@")
	domain := domainParts[len(domainParts)-1]
	exists, err := a.CheckDomain(domain)
	if err != nil {
		http.Error(w, "Failed to check domain: "+err.Error(), http.StatusInternalServerError)
		return
	}

	a.frontendCookie(w, r, "user", clm)

	if exists {
		http.Redirect(w, r, fmt.Sprintf("%s://%s.%s", a.Config.FrontendProto, domain, a.Config.Frontend), http.StatusFound)
	}

	if err := a.setUserOwner(clm); err != nil {
		http.Error(w, "Failed to set user owner: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("%s://%s/company/create", a.Config.FrontendProto, a.Config.Frontend), http.StatusFound)
}

func (a *Account) CheckDomain(domain string) (bool, error) {
	return false, nil
}

func (a *Account) setUserOwner(claims jwx.Claims) error {
	ctx := context.Background()

	client := gocloak.NewClient(a.Config.Keycloak.Hostname)
	token, err := client.LoginAdmin(ctx, a.Config.Keycloak.Username, a.Config.Keycloak.Password, a.Config.Keycloak.RealmName)
	if err != nil {
		return err
	}

	roles, err := client.GetRealmRoles(ctx, token.AccessToken, a.Config.Keycloak.RealmName, gocloak.GetRoleParams{})
	if err != nil {
		return err
	}

	fmt.Sprint(roles)

	// companyOwner := "company_owner"
	// for _, role := range roles {
	// 	if role.Name == &companyOwner {
	// 		if err := client.AddRealmRoleToUser(ctx, token.AccessToken, a.Config.Keycloak.RealmName, claims.Subject, []gocloak.Role{
	// 			{
	// 				ID: role.ID,
	// 			},
	// 		}); err != nil {
	// 			return err
	// 		}
	// 	}
	// }

	return nil
}
