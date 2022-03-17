package account

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/retro-board/backend/internal/backend/company"
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
	ID         string   `json:"id"`
	OriginalID string   `json:"-"`
	Name       string   `json:"name"`
	Role       string   `json:"role"`
	Perms      []string `json:"perms"`

	jwt.RegisteredClaims
}

func NewAccount(config *config.Config) *Account {
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("%s/realms/%s", config.Keycloak.Hostname, config.Keycloak.RealmName))
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

func randString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (a *Account) CheckDomain(domain string) (bool, error) {
	c := company.NewBlankCompany(a.Config)
	c.CTX = a.CTX
	c.CompanyData.Domain = domain

	return c.CheckDomainExists()
}

func getDomain(email string) string {
	domainParts := strings.Split(email, "@")
	fullDomain := domainParts[len(domainParts)-1]
	return strings.Split(fullDomain, ".")[0]
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
