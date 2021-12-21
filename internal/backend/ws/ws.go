package ws

import (
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/gorilla/websocket"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	u := websocket.Upgrader{}
	c, err := u.Upgrade(w, r, nil)
	if err != nil {
		bugLog.Infof("Error upgrading to websocket: %s", err)
		return
	}
	defer func() {
		if err := c.Close(); err != nil {
			bugLog.Infof("Error closing websocket: %s", err)
		}
	}()
}
