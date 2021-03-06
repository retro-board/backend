package main

import (
	"fmt"

	bugLog "github.com/bugfixes/go-bugfixes/logs"

	"github.com/retro-board/backend/internal/backend"
	"github.com/retro-board/backend/internal/config"
)

var (
	BuildVersion string = ""
	BuildHash    string = ""
)

func main() {
	bugLog.Local().Info("Starting Backend")
	bugLog.Local().Info(fmt.Sprintf("Version: %s, Hash: %s", BuildVersion, BuildHash))

	cfg, err := config.Build()
	if err != nil {
		_ = bugLog.Errorf("build config: %v", err)
		return
	}

	b := backend.Backend{
		Config: cfg,
	}

	if err := b.Start(); err != nil {
		_ = bugLog.Errorf("start backend: %v", err)
		return
	}
}
