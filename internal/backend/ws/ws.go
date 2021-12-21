package ws

import (
	"encoding/json"
	"net/http"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/gorilla/websocket"
	"github.com/retro-board/backend/internal/config"
)

type SocketResponse struct {
	Type int
	Data interface{}
}

const (
	TypeTopic          = "topic"
	SubTypeTopicCreate = "create"
	SubTypeTopicDelete = "delete"
	SubTypeTopicVote   = "vote"
	SubTypeTopicUnvote = "unvote"

	TypeLeader                = "leader"
	SubTypeLeaderTimeStart    = "time_start"
	SubTypeLeaderTimeExtend   = "time_extend"
	SubTypeLeaderTimeEnd      = "time_end"
	SubTypeLeaderActionCreate = "action"
	SubTypeLeaderActionDelete = "action_delete"
)

type Sockets interface {
	Perform() (*SocketResponse, error)
}

type WS struct {
	Config *config.Config
}

func Setup(c *config.Config) *WS {
	ws := &WS{
		Config: c,
	}

	return ws
}

// nolint: gocyclo
func (ws *WS) Handler(w http.ResponseWriter, r *http.Request) {
	u := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
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

	clientID := r.URL.Query().Get("client_id")
	boardID := r.URL.Query().Get("board_id")

	if err := ws.validateClient(clientID); err != nil {
		bugLog.Infof("Error validating client: %s", err)
		return
	}
	if err := ws.validateBoard(boardID); err != nil {
		bugLog.Infof("Error validating board: %s", err)
		return
	}

	for {
		_, message, err := c.ReadMessage()
		if err != nil {
			bugLog.Infof("Error reading message: %s", err)
			break
		}

		m, err := parseMessage(ws.Config, clientID, boardID, message)
		if err != nil {
			bugLog.Infof("Error parsing message: %s", err)
			break
		}

		resp, err := m.Perform()
		if err != nil {
			bugLog.Infof("Error performing message: %+v", err)
			if errs := c.WriteMessage(websocket.TextMessage, []byte(err.Error())); errs != nil {
				bugLog.Infof("Error writing message: %s", errs)
			}
			break
		}
		if err := c.WriteJSON(resp); err != nil {
			bugLog.Infof("Error writing message: %+v", err)
			break
		}
	}
}

// nolint: gocyclo
func parseMessage(c *config.Config, clientID, boardID string, message []byte) (Sockets, error) {
	var msg interface{}
	if err := json.Unmarshal(message, &msg); err != nil {
		return nil, err
	}

	// Topic
	if msg.(map[string]interface{})["type"] == TypeTopic {
		t := Topic{
			Config: c,

			ClientID: clientID,
			BoardID:  boardID,
		}

		switch msg.(map[string]interface{})["sub_type"] {
		case SubTypeTopicCreate:
			return parseCreateMessage(t, message)
		case SubTypeTopicDelete:
			return parseDeleteMessage(t, message)
		case SubTypeTopicVote:
			return parseVoteMessage(t, message)
		case SubTypeTopicUnvote:
			return parseUnvoteMessage(t, message)
		}
	}

	// Leader
	if msg.(map[string]interface{})["type"] == TypeLeader {
		l := Leader{
			Config: c,

			ClientID: clientID,
			BoardID:  boardID,
		}

		switch msg.(map[string]interface{})["sub_type"] {
		case SubTypeLeaderActionCreate:
			return parseLeaderActionCreateMessage(l, message)
		case SubTypeLeaderActionDelete:
			return parseLeaderActionDeleteMessage(l, message)
		case SubTypeLeaderTimeStart:
			return parseLeaderTimeStartMessage(l, message)
		case SubTypeLeaderTimeExtend:
			return parseLeaderTimeExtendMessage(l, message)
		case SubTypeLeaderTimeEnd:
			return parseLeaderTimeEndMessage(l, message)
		}
	}

	return nil, nil
}

func parseCreateMessage(t Topic, message []byte) (TopicCreate, error) {
	var msg TopicCreate
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Topic = t

	return msg, nil
}

func parseDeleteMessage(t Topic, message []byte) (TopicDelete, error) {
	var msg TopicDelete
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Topic = t

	return msg, nil
}

func parseVoteMessage(t Topic, message []byte) (TopicVote, error) {
	var msg TopicVote
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Topic = t

	return msg, nil
}

func parseUnvoteMessage(t Topic, message []byte) (TopicUnvote, error) {
	var msg TopicUnvote
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Topic = t

	return msg, nil
}

func parseLeaderTimeStartMessage(l Leader, message []byte) (LeaderTimeStart, error) {
	var msg LeaderTimeStart
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Leader = l

	return msg, nil
}

func parseLeaderActionCreateMessage(l Leader, message []byte) (LeaderActionCreate, error) {
	var msg LeaderActionCreate
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Leader = l

	return msg, nil
}

func parseLeaderActionDeleteMessage(l Leader, message []byte) (LeaderActionDelete, error) {
	var msg LeaderActionDelete
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Leader = l

	return msg, nil
}

func parseLeaderTimeEndMessage(l Leader, message []byte) (LeaderTimeEnd, error) {
	var msg LeaderTimeEnd
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Leader = l

	return msg, nil
}

func parseLeaderTimeExtendMessage(l Leader, message []byte) (LeaderTimeExtend, error) {
	var msg LeaderTimeExtend
	if err := json.Unmarshal(message, &msg); err != nil {
		return msg, err
	}
	msg.Leader = l

	return msg, nil
}
