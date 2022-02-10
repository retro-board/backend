package config

import (
	"errors"

	"github.com/caarlos0/env/v6"
)

type RDS struct {
	Host     string `env:"RDS_HOSTNAME" envDefault:"postgres.retro-board"`
	Port     int    `env:"RDS_PORT" envDefault:"5432"`
	User     string `env:"RDS_USERNAME"`
	Password string `env:"RDS_PASSWORD"`
	DBName   string `env:"RDS_DB" envDefault:"postgres"`
}

func buildDatabase(c *Config) error {
	rds := &RDS{}

	if err := env.Parse(rds); err != nil {
		return err
	}

	if rds.User != "" && rds.Password != "" {
		c.RDS = *rds
		return nil
	}

	pass, err := c.getVaultSecrets("database/creds/backend-role")
	if err != nil {
		return err
	}

	if pass == nil {
		return errors.New("no database password found")
	}

	rds.Password = pass["password"].(string)
	rds.User = pass["username"].(string)
	c.RDS = *rds

	return nil
}
