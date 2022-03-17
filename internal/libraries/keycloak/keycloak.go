package keycloak

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/Nerzal/gocloak/v11"
	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/zemirco/keycloak"
	"golang.org/x/oauth2"
)

type KeycloakRoles struct {
	User   string
	Leader string
	Owner  string
}

type Keycloak struct {
	CTX context.Context

	ClientID     string
	ClientSecret string
	IDOfClient   string

	UserName string
	Password string

	HostName  string
	RealmName string

	Roles KeycloakRoles
}

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type KeycloakRespFormat struct {
	Results []struct {
		Resource struct {
			Name string `json:"name"`
			ID   string `json:"_id"`
		} `json:"resource"`
		Scopes []struct {
			Name string `json:"name"`
			ID   string `json:"_id"`
		} `json:"scopes"`
		Policies []struct {
			Policy struct {
				Name string `json:"name"`
				ID   string `json:"id"`
			} `json:"policy"`
			Status string `json:"status"`
		} `json:"policies"`
		Status string `json:"status"`
	} `json:"results"`
	Status string `json:"status"`
}

type AllScopesStructure struct {
	Resources []struct {
		Scopes []string `json:"scopes"`
	} `json:"resources"`
	Context struct {
		Attributes struct{} `json:"attributes"`
	} `json:"context"`
	RoleIDs      []string `json:"roleIds"`
	ClientID     string   `json:"clientId"`
	UserID       string   `json:"userId"`
	Entitlements bool     `json:"entitlements"`
}

type OwnerStruct struct {
	ID string `json:"id"`
}
type AllowedResources struct {
	Name  string      `json:"name"`
	Owner OwnerStruct `json:"owner"`
	ID    string      `json:"_id"`
}

type AllowedRequest struct {
	Resources []AllowedResources `json:"resources"`
	RoleIDs   []string           `json:"roleIds"`
	ClientID  string             `json:"clientId"`
	UserID    string             `json:"userId"`
}

func CreateKeycloak(ctx context.Context, clientID, clientSecret, IDofClient, userName, password, hostName, realmName string, roles KeycloakRoles) *Keycloak {
	return &Keycloak{
		CTX: ctx,

		ClientID:     clientID,
		ClientSecret: clientSecret,
		IDOfClient:   IDofClient,

		UserName: userName,
		Password: password,

		HostName:  hostName,
		RealmName: realmName,

		Roles: roles,
	}
}

func (k *Keycloak) GetIDOfClient() (string, error) {
	client := gocloak.NewClient(k.HostName)

	token, err := client.GetToken(k.CTX, k.RealmName, gocloak.TokenOptions{
		ClientID:     &k.ClientID,
		ClientSecret: &k.ClientSecret,
		GrantType:    gocloak.StringP("password"),
		Username:     &k.UserName,
		Password:     &k.Password,
	})
	if err != nil {
		return "", bugLog.Error(err)
	}

	clients, err := client.GetClients(k.CTX, token.AccessToken, k.RealmName, gocloak.GetClientsParams{
		ClientID: &k.ClientID,
	})
	if err != nil {
		return "", bugLog.Error(err)
	}
	if len(clients) == 0 {
		return "", bugLog.Error("no client found")
	}

	return *clients[0].ID, nil
}

func (k *Keycloak) GetClient() (*keycloak.Keycloak, error) {
	ctx := context.Background()
	cfg := oauth2.Config{
		ClientID:     k.ClientID,
		ClientSecret: k.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token/", k.HostName, k.RealmName),
		},
	}
	token, err := cfg.PasswordCredentialsToken(ctx, k.UserName, k.Password)
	if err != nil {
		return nil, bugLog.Error(err)
	}
	client := cfg.Client(k.CTX, token)
	kc, err := keycloak.NewKeycloak(client, fmt.Sprintf("%s/", k.HostName))
	if err != nil {
		return nil, bugLog.Error(err)
	}

	return kc, nil
}

func (k *Keycloak) SetUserOwner(userID string) error {
	return k.setRole(userID, k.Roles.Owner)
}

func (k *Keycloak) setRole(userID, roleName string) error {
	client, err := k.GetClient()
	if err != nil {
		return bugLog.Error(err)
	}

	realmRole, resp, err := client.RealmRoles.GetByName(k.CTX, k.RealmName, roleName)
	if err != nil {
		return bugLog.Error(err)
	}

	fmt.Sprintf("rr: %+v, %+v", realmRole, resp)
	return nil

	//
	//
	// client, token, err := k.GetClientAndToken()
	// if err != nil {
	// 	return bugLog.Error(err)
	// }
	//
	// realmRoles, err := client.GetRealmRoles(k.CTX, token.AccessToken, k.RealmName, gocloak.GetRoleParams{
	// 	Search: &roleName,
	// })
	// if err != nil {
	// 	return bugLog.Error(err)
	// }
	// if len(realmRoles) == 0 {
	// 	return bugLog.Error("no role found")
	// }
	//
	// if err := client.AddRealmRoleToUser(k.CTX, token.AccessToken, k.RealmName, userID, []gocloak.Role{
	// 	{
	// 		ID:          realmRoles[0].ID,
	// 		Name:        realmRoles[0].Name,
	// 		ContainerID: realmRoles[0].ContainerID,
	// 	},
	// }); err != nil {
	// 	return bugLog.Error(err)
	// }
	//
	// return nil
}

func (k *Keycloak) SetUserUser(userID string) error {
	return k.setRole(userID, k.Roles.User)
}

func (k *Keycloak) SetUserLeader(userID string) error {
	return k.setRole(userID, k.Roles.Leader)
}

func (k *Keycloak) GetUserRoles(userID string) ([]*gocloak.Role, error) {
	client, err := k.GetClient()
	if err != nil {
		return nil, bugLog.Error(err)
	}

	user, resp, err := client.Users.GetByID(k.CTX, k.RealmName, userID)
	if err != nil {
		return nil, bugLog.Error(err)
	}

	fmt.Sprintf("user: %+v, resp: %+v", user, resp)

	return nil, nil

	// client, token, err := k.GetClientAndToken()
	// if err != nil {
	// 	return nil, bugLog.Error(err)
	// }
	//
	// roles, err := client.GetRealmRolesByUserID(k.CTX, token.AccessToken, k.RealmName, userID)
	// if err != nil {
	// 	return nil, bugLog.Error(err)
	// }
	//
	// return roles, nil
}

func (k *Keycloak) GetUserRole(userID string) (string, error) {
	roles, err := k.GetUserRoles(userID)
	if err != nil {
		return "", bugLog.Error(err)
	}

	if len(roles) == 0 {
		return "", bugLog.Error("no roles found")
	}

	for _, role := range roles {
		switch *role.Name {
		case k.Roles.User:
			return k.Roles.User, nil
		case k.Roles.Leader:
			return k.Roles.Leader, nil
		case k.Roles.Owner:
			return k.Roles.Owner, nil
		}
	}

	return k.Roles.User, nil
}

func (k *Keycloak) IsAllowed(userID, userRole, permissionName string) (bool, error) {
	// _, token, err := k.GetClientAndToken()
	// if err != nil {
	// 	return false, bugLog.Error(err)
	// }
	//
	// idOfClient, err := k.GetIDOfClient()
	// if err != nil {
	// 	return false, bugLog.Error(err)
	// }
	// k.IDOfClient = idOfClient
	//
	// res, err := k.GetResourceID(permissionName)
	// if err != nil {
	// 	return false, bugLog.Error(err)
	// }
	//
	// ar := AllowedRequest{
	// 	RoleIDs:  []string{userRole},
	// 	ClientID: idOfClient,
	// 	UserID:   userID,
	// 	Resources: []AllowedResources{
	// 		{
	// 			Name: permissionName,
	// 			Owner: OwnerStruct{
	// 				ID: idOfClient,
	// 			},
	// 			ID: res,
	// 		},
	// 	},
	// }
	//
	// result, err := k.sendRequest(ar, token)
	// if err != nil {
	// 	return false, bugLog.Error(err)
	// }
	//
	// if len(result.Results) == 0 {
	// 	return false, nil
	// }
	//
	// if result.Status == "PERMIT" {
	// 	return true, nil
	// }

	return false, nil
}

func (k *Keycloak) GetResourceID(resourceName string) (string, error) {
	return "", nil

	// client, token, err := k.GetClientAndToken()
	// if err != nil {
	// 	return "", bugLog.Error(err)
	// }
	//
	// idOfClient, err := k.GetIDOfClient()
	// if err != nil {
	// 	return "", bugLog.Error(err)
	// }
	//
	// res, err := client.GetResources(k.CTX, token.AccessToken, k.RealmName, idOfClient, gocloak.GetResourceParams{
	// 	Name: &resourceName,
	// })
	// if err != nil {
	// 	return "", bugLog.Error(err)
	// }
	// if len(res) == 0 {
	// 	return "", bugLog.Error("no resource found")
	// }
	//
	// return *res[0].ID, nil
}

func (k *Keycloak) getTokenAndIDofClient() (*gocloak.JWT, string, error) {
	jwt := &gocloak.JWT{}
	return jwt, "", nil

	// _, token, err := k.GetClientAndToken()
	// if err != nil {
	// 	return jwt, "", bugLog.Error(err)
	// }
	// jwt = token
	//
	// idOfClient, err := k.GetIDOfClient()
	// if err != nil {
	// 	return jwt, "", bugLog.Error(err)
	// }
	//
	// return jwt, idOfClient, nil
}

func (k *Keycloak) GetAllUserScopes(userID string) ([]string, error) {
	token, idOfClient, err := k.getTokenAndIDofClient()
	if err != nil {
		return []string{}, bugLog.Error(err)
	}
	k.IDOfClient = idOfClient

	ar := AllScopesStructure{
		Resources: []struct {
			Scopes []string `json:"scopes"`
		}{
			{
				Scopes: []string{},
			},
		},
		Context: struct {
			Attributes struct{} `json:"attributes"`
		}{
			Attributes: struct{}{},
		},
		RoleIDs:      []string{},
		ClientID:     idOfClient,
		UserID:       userID,
		Entitlements: false,
	}

	result, err := k.sendRequest(ar, token)
	if err != nil {
		return []string{}, bugLog.Error(err)
	}

	if len(result.Results) == 0 {
		return []string{}, nil
	}

	resultSet := []string{}

	for _, res := range result.Results {
		scopes := res.Scopes
		policies := res.Policies

		if len(scopes) == 1 && len(policies) == 1 {
			if policies[0].Status == "PERMIT" {
				resultSet = append(resultSet, scopes[0].Name)
			}
		}
	}

	return resultSet, nil
}

func (k *Keycloak) sendRequest(request interface{}, token *gocloak.JWT) (*KeycloakRespFormat, error) {
	ret := &KeycloakRespFormat{}

	j, err := json.Marshal(request)
	if err != nil {
		return ret, bugLog.Error(err)
	}

	hc := &http.Client{}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf(
			"%s/auth/admin/realms/%s/clients/%s/authz/resource-server/policy/evaluate",
			k.HostName,
			k.RealmName,
			k.IDOfClient), bytes.NewBuffer(j))
	if err != nil {
		return ret, bugLog.Error(err)
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return ret, bugLog.Error(err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&ret); err != nil {
		return ret, bugLog.Error(err)
	}

	return ret, nil
}

func (k *Keycloak) GetTokens() (*Tokens, error) {
	t := &Tokens{}

	hc := &http.Client{}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", k.HostName, k.RealmName),
		strings.NewReader(url.Values{
			"grant_type": {"password"},
			"username":   {k.UserName},
			"password":   {k.Password},
		}.Encode()))
	if err != nil {
		return t, bugLog.Error(err)
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", k.getBasic()))
	resp, err := hc.Do(req)
	if err != nil {
		return t, bugLog.Error(err)
	}

	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(t); err != nil {
		return t, bugLog.Error(err)
	}

	return t, nil
}

func (k *Keycloak) getBasic() string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", k.ClientID, k.ClientSecret)))
}

func (k *Keycloak) GetClientID(tokens *Tokens) (string, error) {
	hc := &http.Client{}
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf("%s/admin/realms/%s/clients", k.HostName, k.RealmName),
		nil,
	)
	if err != nil {
		return "", bugLog.Error(err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))

	query := req.URL.Query()
	query.Add("clientId", k.ClientID)
	req.URL.RawQuery = query.Encode()

	resp, err := hc.Do(req)
	if err != nil {
		return "", bugLog.Error(err)
	}
	defer resp.Body.Close()
	e, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", bugLog.Error(err)
	}

	ee := fmt.Sprintf("%s", e)
	fmt.Sprint(ee)

	return "", nil
}
