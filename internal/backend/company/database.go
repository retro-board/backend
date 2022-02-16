package company

import (
	"context"
	"errors"
	"fmt"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/jackc/pgx/v4"
)

func (c *Company) getConnection(ctx context.Context) (*pgx.Conn, error) {
	conn, err := pgx.Connect(ctx, fmt.Sprintf(
		"postgresql://%s:%s@%s:%d/%s",
		c.Config.RDS.User,
		c.Config.RDS.Password,
		c.Config.RDS.Host,
		c.Config.RDS.Port,
		c.Config.RDS.DBName,
	))
	if err != nil {
		return nil, bugLog.Error(err)
	}

	return conn, nil
}

func (c *Company) addCompanyToDatabase(ctx context.Context) error {
	conn, err := c.getConnection(ctx)
	if err != nil {
		return bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(ctx); err != nil {
			bugLog.Debugf("addCompanyToDatabase disconnect: %+v", err)
		}
	}()

	if _, err := conn.Exec(ctx,
		`INSERT INTO company (name, subdomain, domain) VALUES ($1, $2, $3)`,
		c.CompanyData.Name,
		c.CompanyData.SubDomain,
		c.CompanyData.Domain); err != nil {
		return bugLog.Error(err)
	}

	c.CompanyData.Enabled = true
	return nil
}

func (c *Company) CheckDomainExists(ctx context.Context) (bool, error) {
	conn, err := c.getConnection(ctx)
	if err != nil {
		return false, bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(ctx); err != nil {
			bugLog.Debugf("CheckDomainExists disconnect: %+v", err)
		}
	}()

	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM company WHERE domain = $1)`,
		c.CompanyData.Domain).Scan(&exists); err != nil {
		return false, bugLog.Error(err)
	}

	return exists, nil
}

func (c *Company) CheckSubDomainExists(ctx context.Context) (bool, error) {
	conn, err := c.getConnection(ctx)
	if err != nil {
		return false, bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(ctx); err != nil {
			bugLog.Debugf("CheckSubDomainExists disconnect: %+v", err)
		}
	}()

	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM company WHERE subdomain = $1)`,
		c.CompanyData.SubDomain).Scan(&exists); err != nil {
		return false, errors.New("subdomain already exists")
	}

	return exists, nil
}

func (c *Company) GetCompanyData() error {
	conn, err := c.getConnection(context.Background())
	if err != nil {
		return bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			bugLog.Debugf("GetCompanyData disconnect: %+v", err)
		}
	}()

	var name, subDomain, domain string
	if err := conn.QueryRow(context.Background(),
		`SELECT name, subdomain, domain FROM company WHERE domain = $1`,
		c.CompanyData.Domain).Scan(
		&name,
		&subDomain,
		&domain); err != nil {
		return bugLog.Error(err)
	}

	c.CompanyData.Name = name
	c.CompanyData.SubDomain = subDomain
	c.CompanyData.Domain = domain
	c.CompanyData.Enabled = true

	return nil
}
