package company

import (
	"context"
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
		`INSERT INTO company (name, formatted_name, keycloak_id) VALUES ($1, $2, $3)`,
		c.Name,
		c.FormattedName,
		c.ID); err != nil {
		return bugLog.Error(err)
	}

	return nil
}

func (c *Company) companyDomainExists(ctx context.Context) (bool, error) {
	conn, err := c.getConnection(ctx)
	if err != nil {
		return false, bugLog.Error(err)
	}

	defer func() {
		if err := conn.Close(ctx); err != nil {
			bugLog.Debugf("companyDomainExists disconnect: %+v", err)
		}
	}()

	var exists bool
	if err := conn.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM company WHERE formatted_name = $1)`,
		c.FormattedName).Scan(&exists); err != nil {
		return false, bugLog.Error(err)
	}

	return exists, nil
}
