package config

import (
	"github.com/caarlos0/env/v6"
)

type Kubernetes struct {
	ClusterIssuer string `env:"CLUSTER_ISSUER"`
	Namespace     string `env:"NAMESPACE" envDefault:"retro-board"`
}

func buildKubernetes(c *Config) error {
	kube := Kubernetes{}
	if err := env.Parse(&kube); err != nil {
		return err
	}

	c.Kubernetes = kube

	return nil
}
