package company

import (
	"context"

	"github.com/Nerzal/gocloak/v10"
	bugLog "github.com/bugfixes/go-bugfixes/logs"
)

func (c *Company) addCompanyToKeycloak(ctx context.Context) error {
	gc := gocloak.NewClient(c.Config.Keycloak.Hostname)
	token, err := gc.LoginAdmin(ctx, c.Config.Keycloak.Username, c.Config.Keycloak.Password, c.Config.Keycloak.RealmName)
	if err != nil {
		return bugLog.Error(err)
	}

	return c.createDefaultGroups(ctx, gc, token)
}

func (c *Company) createDefaultGroups(ctx context.Context, gc gocloak.GoCloak, token *gocloak.JWT) error {
	realmName := c.Config.Keycloak.RealmName

	cgid, err := createGroupAttachRole(ctx, gc, token, realmName, c.FormattedName, "CompanyUser")
	if err != nil {
		return bugLog.Error(err)
	}
	c.ID = cgid

	if err := createChildGroupAttachRole(ctx, gc, token, realmName, "admins", cgid, "CompanyAdmin"); err != nil {
		return bugLog.Error(err)
	}

	if err := createChildGroupAttachRole(ctx, gc, token, realmName, "leaders", cgid, "SprintLeader"); err != nil {
		return bugLog.Error(err)
	}

	return nil
}

func getRole(ctx context.Context, gc gocloak.GoCloak, token *gocloak.JWT, realmName string, roleName string) (gocloak.Role, error) {
	role, err := gc.GetRealmRole(ctx, token.AccessToken, realmName, roleName)
	if err != nil {
		return gocloak.Role{}, bugLog.Error(err)
	}

	return *role, nil
}

func attachRoleToGroup(ctx context.Context, gc gocloak.GoCloak, token *gocloak.JWT, realmName string, groupID, roleName string) error {
	role, err := getRole(ctx, gc, token, realmName, roleName)
	if err != nil {
		return bugLog.Error(err)
	}

	return gc.AddRealmRoleToGroup(ctx, token.AccessToken, realmName, groupID, []gocloak.Role{role})
}

func createGroupAttachRole(ctx context.Context, gc gocloak.GoCloak, token *gocloak.JWT, realmName, groupName, roleName string) (string, error) {
	kg := gocloak.Group{
		Name: &groupName,
	}
	groupID, err := gc.CreateGroup(ctx, token.AccessToken, realmName, kg)
	if err != nil {
		return "", bugLog.Error(err)
	}
	if err := attachRoleToGroup(ctx, gc, token, realmName, groupID, roleName); err != nil {
		return "", bugLog.Error(err)
	}

	return groupID, nil
}

func createChildGroupAttachRole(ctx context.Context, gc gocloak.GoCloak, token *gocloak.JWT, realmName, groupName, parentID, roleName string) error {
	kg := gocloak.Group{
		Name: &groupName,
	}
	groupID, err := gc.CreateChildGroup(ctx, token.AccessToken, realmName, parentID, kg)
	if err != nil {
		return bugLog.Error(err)
	}
	if err := attachRoleToGroup(ctx, gc, token, realmName, groupID, roleName); err != nil {
		return bugLog.Error(err)
	}

	return nil
}
