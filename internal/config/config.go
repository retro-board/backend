package config

import (
	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/caarlos0/env/v6"
)

type Local struct {
	KeepLocal     bool   `env:"LOCAL_ONLY" envDefault:"false"`
	Development   bool   `env:"DEVELOPMENT" envDefault:"false"`
	Port          int    `env:"PORT" envDefault:"3000"`
	Frontend      string `env:"FRONTEND_URL" envDefault:"retro-board.it"`
	FrontendProto string `env:"FRONTEND_PROTO" envDefault:"https"`
}

type Config struct {
	Local
	RDS
	Vault
	Keycloak
}

func Build() (*Config, error) {
	cfg := &Config{}

	if err := env.Parse(cfg); err != nil {
		return nil, bugLog.Error(err)
	}

	if err := buildDatabase(cfg); err != nil {
		return nil, bugLog.Error(err)
	}

	if err := buildVault(cfg); err != nil {
		return nil, bugLog.Error(err)
	}

	if err := buildKeycloak(cfg); err != nil {
		return nil, bugLog.Error(err)
	}

	return cfg, nil
}
