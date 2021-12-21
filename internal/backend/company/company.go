package company

import (
	"context"
	"strings"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/retro-board/backend/internal/config"
)

type Company struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	FormattedName string

	Config *config.Config
}

func NewBlankCompany(c *config.Config) *Company {
	return &Company{
		ID:            "",
		Name:          "Blank Company",
		FormattedName: "Blank-Company",
		Config:        c,
	}
}

func (c *Company) setFormattedName(name string) {
	c.FormattedName = strings.Replace(name, " ", "-", -1)
}

func (c *Company) CreateCompany(name string) error {
	c.setFormattedName(name)
	c.Name = name

	ctx := context.Background()

	if domainExists, err := c.companyDomainExists(ctx); err != nil {
		return bugLog.Error(err)
	} else if domainExists {
		return nil
	}

	if err := c.addCompanyToKeycloak(ctx); err != nil {
		return bugLog.Error(err)
	}

	if err := c.addCompanyToDatabase(ctx); err != nil {
		return bugLog.Error(err)
	}

	return nil
}
