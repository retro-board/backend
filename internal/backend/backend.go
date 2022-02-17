package backend

import (
	"fmt"
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	bugMiddleware "github.com/bugfixes/go-bugfixes/middleware"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/go-chi/httplog"
	"github.com/retro-board/backend/internal/backend/account"
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

	allowedOrigins := []string{
		"https://retro-board.it",
		"https://*.retro-board.it",
	}
	if b.Config.Development {
		allowedOrigins = append(allowedOrigins, "http://*")
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token", "X-User-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	})

	r := chi.NewRouter()
	r.Use(httplog.RequestLogger(logger))
	r.Use(middleware.RequestID)
	r.Use(middleware.Heartbeat("/ping"))
	r.Use(c.Handler)
	r.Use(bugMiddleware.BugFixes)

	r.HandleFunc("/ws", ws.Setup(b.Config).Handler)

	r.Route("/company", func(r chi.Router) {
		r.Post("/", company.NewBlankCompany(b.Config).CreateHandler)
	})

	r.Route("/board", func(r chi.Router) {
		r.Route("/{boardID}", func(r chi.Router) {
			r.Get("/", board.NewBoard(b.Config).GetHandler)
		})
	})
	r.Route("/boards", func(r chi.Router) {
		r.Get("/", board.NewBoard(b.Config).GetAllHandler)
	})

	r.Route("/account", func(r chi.Router) {
		r.Get("/login", account.NewAccount(b.Config).LoginHandler)
		r.Get("/callback", account.NewAccount(b.Config).CallbackHandler)
	})

	bugLog.Local().Infof("listening on %d\n", b.Config.Local.Port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", b.Config.Local.Port), r); err != nil {
		return bugLog.Errorf("port failed: %+v", err)
	}

	return nil
}
