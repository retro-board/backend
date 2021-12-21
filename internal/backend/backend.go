package backend

import (
	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/retro-board/backend/internal/backend/company"
	"github.com/retro-board/backend/internal/config"
)

type Backend struct {
	Config *config.Config
}

func (b Backend) Start() error {
	c := company.NewBlankCompany(b.Config)
	if err := c.CreateCompany("tester"); err != nil {
		return bugLog.Error(err)
	}

	return nil
}
