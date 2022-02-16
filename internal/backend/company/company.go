package company

import (
	"context"
	"errors"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/golang-jwt/jwt/v4"
	"github.com/retro-board/backend/internal/config"
)

type Company struct {
	Config *config.Config
	CTX    context.Context

	CompanyData CompanyData
}

type CompanyData struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SubDomain string `json:"subdomain"`
	Domain    string `json:"domain"`
	Enabled   bool   `json:"enabled"`

	jwt.RegisteredClaims
}

func NewBlankCompany(c *config.Config) *Company {
	cd := CompanyData{
		ID:        "",
		Name:      "Blank Company",
		SubDomain: "blank-company",
		Enabled:   false,
	}

	return &Company{
		Config: c,

		CompanyData: cd,
	}
}

func (c *Company) CreateCompany() error {
	ctx := context.Background()

	if domainExists, err := c.CheckDomainExists(ctx); err != nil {
		return bugLog.Error(err)
	} else if domainExists {
		return nil
	}
	if subdomainExists, err := c.CheckSubDomainExists(ctx); err != nil {
		return bugLog.Error(err)
	} else if subdomainExists {
		return errors.New("subdomain already exists")
	}

	if err := c.addCompanyToDatabase(ctx); err != nil {
		return bugLog.Error(err)
	}

	return nil
}
