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

type Keycloak struct {
	CTX context.Context

	ClientID     string
	ClientSecret string
	IdOfClient   string

	UserName string
	Password string

	HostName  string
	RealmName string
}

func CreateKeycloak(ctx context.Context, clientID, clientSecret, userName, password, hostName, realmName string) *Keycloak {
	return &Keycloak{
		CTX: ctx,

		ClientID:     clientID,
		ClientSecret: clientSecret,

		UserName: userName,
		Password: password,

		HostName:  hostName,
		RealmName: realmName,
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

func (k *Keycloak) SetUserOwner(userId, roleName string) error {
	client, token, err := k.GetClientAndToken()
	if err != nil {
		return bugLog.Error(err)
	}

	roles, err := client.GetRealmRoles(k.CTX, token.AccessToken, k.RealmName, gocloak.GetRoleParams{
		Search: &roleName,
	})
	if len(roles) == 0 {
		return bugLog.Error("no role found")
	}

	if err := client.AddRealmRoleToUser(k.CTX, token.AccessToken, k.RealmName, userId, []gocloak.Role{
		{
			ID:          roles[0].ID,
			Name:        roles[0].Name,
			ContainerID: roles[0].ContainerID,
		},
	}); err != nil {
		return bugLog.Error(err)
	}

	return nil
}

func (k *Keycloak) GetUserRoles(userId string) ([]*gocloak.Role, error) {
	client, token, err := k.GetClientAndToken()
	if err != nil {
		return nil, bugLog.Error(err)
	}

	roles, err := client.GetRealmRolesByUserID(k.CTX, token.AccessToken, k.RealmName, userId)
	if err != nil {
		return nil, bugLog.Error(err)
	}

	return roles, nil
}

func (k *Keycloak) IsAllowed(userId, roleName, permissionName string) (bool, error) {
	_, token, err := k.GetClientAndToken()
	if err != nil {
		return false, bugLog.Error(err)
	}

	idOfClient, err := k.GetIDOfClient()
	if err != nil {
		return false, bugLog.Error(err)
	}
	k.IdOfClient = idOfClient

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
		UserId    string             `json:"userId"`
	}

	ar := AllowedRequest{
		RoleIDs:  []string{roleName},
		ClientID: idOfClient,
		UserId:   userId,
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

	if result.Status == "PERMIT" {
		return true, nil
	}

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
	if len(res) == 0 {
		return "", bugLog.Error("no resource found")
	}

	return *res[0].ID, nil
}
