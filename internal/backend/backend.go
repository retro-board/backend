package backend

import (
	"fmt"
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	bugmiddleware "github.com/bugfixes/go-bugfixes/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog"
	"github.com/retro-board/backend/internal/backend/board"
	"github.com/retro-board/backend/internal/backend/company"
	"github.com/retro-board/backend/internal/backend/ws"
	"github.com/retro-board/backend/internal/config"
)

type Backend struct {
	Config *config.Config
}

func (b Backend) Start() error {
	bugLog.Local().Info("Starting API")

	logger := httplog.NewLogger("retro-board-api", httplog.Options{
		JSON: true,
	})

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})

	r := chi.NewRouter()
	r.Use(httplog.RequestLogger(logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(c.Handler)
	r.Use(bugmiddleware.BugFixes)

	r.HandleFunc("/ws", ws.Setup(b.Config).Handler)

	r.Route("/company", func(r chi.Router) {
		r.Post("/", company.NewBlankCompany(b.Config).CreateHandler)
	})

	r.Route("/board", func(r chi.Router) {
		r.Route("/{boardID}", func(r chi.Router) {
			r.Get("/client", board.NewBoard(b.Config).SetupClientHandler)
			r.Get("/", board.NewBoard(b.Config).GetHandler)
		})
	})

	bugLog.Local().Infof("listening on %d\n", b.Config.Local.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", b.Config.Local.Port), r); err != nil {
		return bugLog.Errorf("port failed: %+v", err)
	}

	return nil
}
