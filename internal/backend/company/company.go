package company

import (
	"context"
	"errors"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/golang-jwt/jwt/v4"
	"github.com/retro-board/backend/internal/backend/kube"
	"github.com/retro-board/backend/internal/config"
)

type Company struct {
	Config *config.Config
	CTX    context.Context

	CompanyData CompanyData
}

type CompanyData struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	SubDomain string `json:"subdomain"`
	Domain    string `json:"domain"`
	Enabled   bool   `json:"enabled"`

	jwt.RegisteredClaims
}

func NewBlankCompany(c *config.Config) *Company {
	cd := CompanyData{
		ID:        0,
		Name:      "Blank Company",
		SubDomain: "blank-company",
		Enabled:   false,
	}

	return &Company{
		Config: c,

		CompanyData: cd,
	}
}

func (c *Company) CreateCompany(firstTeamName string) error {
	if domainExists, err := c.CheckDomainExists(); err != nil {
		return bugLog.Error(err)
	} else if domainExists {
		return nil
	}
	if subdomainExists, err := c.CheckSubDomainExists(); err != nil {
		return bugLog.Error(err)
	} else if subdomainExists {
		return errors.New("subdomain already exists")
	}

	frontend := c.Config.Frontend
	if c.Config.Development {
		frontend = "retro-board.it"
	}

	if err := kube.NewKube(
		c.CTX,
		c.Config.Development,
		c.CompanyData.SubDomain,
		frontend,
		c.Config.Kubernetes.ClusterIssuer,
		c.Config.Kubernetes.Namespace).CreateSubdomain(); err != nil {
		return bugLog.Error(err)
	}

	if err := c.addCompanyToDatabase(firstTeamName); err != nil {
		return bugLog.Error(err)
	}

	c.CompanyData.Enabled = true

	return nil
}
