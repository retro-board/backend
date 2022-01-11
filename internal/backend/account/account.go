package account

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"

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

func NewAccount(config *config.Config) *Account {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("%s/auth/realms/%s", config.Keycloak.Hostname, config.Keycloak.RealmName))
	if err != nil {
		bugLog.Infof("provider failed: %+v", err)
	}
	oidcConfig := &oidc.Config{
		ClientID: config.Keycloak.Username,
	}
	verifier := provider.Verifier(oidcConfig)
	oauthConfig := oauth2.Config{
		ClientID:     config.Keycloak.Username,
		ClientSecret: config.Keycloak.Password,
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

	fmt.Printf("callback happened")
}
