package company

import (
	"context"
	"errors"
	"fmt"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	pgx "github.com/jackc/pgx/v4"
)

func (c *Company) getConnection() (*pgx.Conn, error) {
	conn, err := pgx.Connect(c.CTX, fmt.Sprintf(
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

func (c *Company) addCompanyToDatabase(firstTeamName string) error {
	conn, err := c.getConnection()
	if err != nil {
		return bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(c.CTX); err != nil {
			bugLog.Debugf("addCompanyToDatabase disconnect: %+v", err)
		}
	}()

	var companyId int
	if err := conn.QueryRow(c.CTX,
		`INSERT INTO company (name, subdomain, domain) VALUES ($1, $2, $3) RETURNING id`,
		c.CompanyData.Name,
		c.CompanyData.SubDomain,
		c.CompanyData.Domain).Scan(&companyId); err != nil {
		return bugLog.Error(err)
	}

	c.CompanyData.ID = companyId
	c.CompanyData.Enabled = true

	if err := c.addBoardToDatabase(firstTeamName); err != nil {
		return bugLog.Error(err)
	}

	return nil
}

func (c *Company) addBoardToDatabase(firstTeamName string) error {
	conn, err := c.getConnection()
	if err != nil {
		return bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(c.CTX); err != nil {
			bugLog.Debugf("addCompanyToDatabase disconnect: %+v", err)
		}
	}()
	if _, err := conn.Exec(c.CTX,
		`INSERT INTO board (company_id, name) VALUES ($1, $2)`,
		c.CompanyData.ID,
		firstTeamName); err != nil {
		return bugLog.Error(err)
	}

	return nil
}

func (c *Company) CheckDomainExists() (bool, error) {
	conn, err := c.getConnection()
	if err != nil {
		return false, bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(c.CTX); err != nil {
			bugLog.Debugf("CheckDomainExists disconnect: %+v", err)
		}
	}()

	var exists bool
	if err := conn.QueryRow(c.CTX,
		`SELECT EXISTS(SELECT 1 FROM company WHERE domain = $1)`,
		c.CompanyData.Domain).Scan(&exists); err != nil {
		return false, bugLog.Error(err)
	}

	return exists, nil
}

func (c *Company) CheckSubDomainExists() (bool, error) {
	conn, err := c.getConnection()
	if err != nil {
		return false, bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(c.CTX); err != nil {
			bugLog.Debugf("CheckSubDomainExists disconnect: %+v", err)
		}
	}()

	var exists bool
	if err := conn.QueryRow(c.CTX,
		`SELECT EXISTS(SELECT 1 FROM company WHERE subdomain = $1)`,
		c.CompanyData.SubDomain).Scan(&exists); err != nil {
		return false, errors.New("subdomain already exists")
	}

	return exists, nil
}

func (c *Company) GetCompanyData() error {
	conn, err := c.getConnection()
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

	bugLog.Logf("preset: %+v", c.CompanyData)

	c.CompanyData.Name = name
	c.CompanyData.SubDomain = subDomain
	c.CompanyData.Domain = domain
	c.CompanyData.Enabled = true

	bugLog.Logf("postset: %+v", c.CompanyData)

	return nil
}
