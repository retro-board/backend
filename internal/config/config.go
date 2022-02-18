package config

import (
	"fmt"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/caarlos0/env/v6"
)

type Local struct {
	KeepLocal   bool `env:"LOCAL_ONLY" envDefault:"false"`
	Development bool `env:"DEVELOPMENT" envDefault:"false"`
	Port        int  `env:"PORT" envDefault:"3000"`

	Frontend      string `env:"FRONTEND_URL" envDefault:"retro-board.it"`
	FrontendProto string `env:"FRONTEND_PROTO" envDefault:"https"`
	JWTSecret     string `env:"JWT_SECRET" envDefault:"retro-board"`
	TokenSeed     string `env:"TOKEN_SEED" envDefault:"retro-board"`
}

type Config struct {
	Local
	RDS
	Vault
	Keycloak
	Kubernetes
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

	if err := buildLocal(cfg); err != nil {
		return nil, bugLog.Error(err)
	}

	if err := buildKubernetes(cfg); err != nil {
		return nil, bugLog.Error(err)
	}

	return cfg, nil
}

func buildLocal(cfg *Config) error {
	vaultSecrets, err := cfg.getVaultSecrets("kv/data/retro-board/local-keys")
	if err != nil {
		return err
	}

	if vaultSecrets == nil {
		return fmt.Errorf("local keys not found in vault")
	}

	secrets, err := ParseKVSecrets(vaultSecrets)
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		if secret.Key == "jwt-secret" {
			cfg.Local.JWTSecret = secret.Value
		}

		if secret.Key == "user-token" {
			cfg.Local.TokenSeed = secret.Value
		}
	}

	return nil
}
