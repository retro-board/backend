package keycloak

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Nerzal/gocloak/v10"
	bugLog "github.com/bugfixes/go-bugfixes/logs"
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

func CreateKeycloak(ctx context.Context, clientID, clientSecret, userName, password, hostName, realmName string, roles KeycloakRoles) *Keycloak {
	return &Keycloak{
		CTX: ctx,

		ClientID:     clientID,
		ClientSecret: clientSecret,

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

func (k *Keycloak) GetClientAndToken() (gocloak.GoCloak, *gocloak.JWT, error) {
	client := gocloak.NewClient(k.HostName)
	token, err := client.GetToken(k.CTX, k.RealmName, gocloak.TokenOptions{
		ClientID:     &k.ClientID,
		ClientSecret: &k.ClientSecret,
		GrantType:    gocloak.StringP("password"),
		Username:     &k.UserName,
		Password:     &k.Password,
	})
	if err != nil {
		return nil, nil, bugLog.Error(err)
	}

	return client, token, nil
}

func (k *Keycloak) SetUserOwner(userID string) error {
	return k.setRole(userID, k.Roles.Owner)
}

func (k *Keycloak) setRole(userID, roleName string) error {
	client, token, err := k.GetClientAndToken()
	if err != nil {
		return bugLog.Error(err)
	}

	realmRoles, err := client.GetRealmRoles(k.CTX, token.AccessToken, k.RealmName, gocloak.GetRoleParams{
		Search: &roleName,
	})
	if err != nil {
		return bugLog.Error(err)
	}
	if len(realmRoles) == 0 {
		return bugLog.Error("no role found")
	}

	if err := client.AddRealmRoleToUser(k.CTX, token.AccessToken, k.RealmName, userID, []gocloak.Role{
		{
			ID:          realmRoles[0].ID,
			Name:        realmRoles[0].Name,
			ContainerID: realmRoles[0].ContainerID,
		},
	}); err != nil {
		return bugLog.Error(err)
	}

	return nil
}

func (k *Keycloak) SetUserUser(userID string) error {
	return k.setRole(userID, k.Roles.User)
}

func (k *Keycloak) SetUserLeader(userID string) error {
	return k.setRole(userID, k.Roles.Leader)
}

func (k *Keycloak) GetUserRoles(userID string) ([]*gocloak.Role, error) {
	client, token, err := k.GetClientAndToken()
	if err != nil {
		return nil, bugLog.Error(err)
	}

	roles, err := client.GetRealmRolesByUserID(k.CTX, token.AccessToken, k.RealmName, userID)
	if err != nil {
		return nil, bugLog.Error(err)
	}

	return roles, nil
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
	_, token, err := k.GetClientAndToken()
	if err != nil {
		return false, bugLog.Error(err)
	}

	idOfClient, err := k.GetIDOfClient()
	if err != nil {
		return false, bugLog.Error(err)
	}
	k.IDOfClient = idOfClient

	res, err := k.GetResourceID(permissionName)
	if err != nil {
		return false, bugLog.Error(err)
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

	ar := AllowedRequest{
		RoleIDs:  []string{userRole},
		ClientID: idOfClient,
		UserID:   userID,
		Resources: []AllowedResources{
			{
				Name: permissionName,
				Owner: OwnerStruct{
					ID: idOfClient,
				},
				ID: res,
			},
		},
	}
	j, err := json.Marshal(ar)
	if err != nil {
		return false, bugLog.Error(err)
	}

	hc := &http.Client{}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf(
			"%s/auth/admin/realms/%s/clients/%s/authz/resource-server/policy/evaluate",
			k.HostName,
			k.RealmName,
			idOfClient), bytes.NewBuffer(j))
	if err != nil {
		return false, bugLog.Error(err)
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return false, bugLog.Error(err)
	}
	defer resp.Body.Close()

	type respFormat struct {
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

	// var testResult interface{}
	// if err := json.NewDecoder(resp.Body).Decode(&testResult); err != nil {
	// 	return false, bugLog.Error(err)
	// }
	result := respFormat{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, bugLog.Error(err)
	}

	if len(result.Results) == 0 {
		return false, nil
	}

	if result.Status == "PERMIT" {
		return true, nil
	}

	// for _, res := range result.Results {
	// 	if len(res.Policies) == 0 {
	// 		return false, nil
	// 	}
	// 	for _, pol := range res.Policies {
	// 		if pol.Status == "PERMIT" {
	// 			return true, nil
	// 		}
	// 	}
	// }

	return false, nil
}

func (k *Keycloak) GetResourceID(resourceName string) (string, error) {
	client, token, err := k.GetClientAndToken()
	if err != nil {
		return "", bugLog.Error(err)
	}

	idOfClient, err := k.GetIDOfClient()
	if err != nil {
		return "", bugLog.Error(err)
	}

	res, err := client.GetResources(k.CTX, token.AccessToken, k.RealmName, idOfClient, gocloak.GetResourceParams{
		Name: &resourceName,
	})
	if err != nil {
		return "", bugLog.Error(err)
	}
	if len(res) == 0 {
		return "", bugLog.Error("no resource found")
	}

	return *res[0].ID, nil
}

func (k *Keycloak) GetAllUserScopes(userID string) ([]string, error) {
	_, token, err := k.GetClientAndToken()
	if err != nil {
		return []string{}, bugLog.Error(err)
	}

	idOfClient, err := k.GetIDOfClient()
	if err != nil {
		return []string{}, bugLog.Error(err)
	}
	k.IDOfClient = idOfClient

	type reqStruct struct {
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

	ar := reqStruct{
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

	j, err := json.Marshal(ar)
	if err != nil {
		return []string{}, bugLog.Error(err)
	}
	fmt.Printf("%s", j)

	hc := &http.Client{}
	req, err := http.NewRequest(
		"POST",
		fmt.Sprintf(
			"%s/auth/admin/realms/%s/clients/%s/authz/resource-server/policy/evaluate",
			k.HostName,
			k.RealmName,
			idOfClient), bytes.NewBuffer(j))
	if err != nil {
		return []string{}, bugLog.Error(err)
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	req.Header.Add("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return []string{}, bugLog.Error(err)
	}
	defer resp.Body.Close()

	type respFormat struct {
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

	result := respFormat{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
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
