package ws

import (
	"github.com/retro-board/backend/internal/config"
)

type Leader struct {
	Config *config.Config

	ClientID string
	BoardID  string
}

type LeaderTimeStart struct {
	Leader Leader

	Type    string `json:"type"`
	TopicID string `json:"topic_id"`
}
type LeaderTimeExtend struct {
	Leader Leader

	Type    string `json:"type"`
	TimerID int    `json:"timer_id"`
}
type LeaderTimeEnd struct {
	Leader Leader

	Type    string `json:"type"`
	TimerID int    `json:"timer_id"`
}
type LeaderActionCreate struct {
	Leader Leader

	Type    string `json:"type"`
	Content string `json:"content"`
}
type LeaderActionDelete struct {
	Leader Leader

	Type     string `json:"type"`
	ActionID int    `json:"action_id"`
}

func (l LeaderTimeStart) Perform() (*SocketResponse, error) {
	return nil, nil
}

func (l LeaderTimeExtend) Perform() (*SocketResponse, error) {
	return nil, nil
}

func (l LeaderTimeEnd) Perform() (*SocketResponse, error) {
	return nil, nil
}

func (LeaderActionCreate) Perform() (*SocketResponse, error) {
	return nil, nil
}

func (l LeaderActionDelete) Perform() (*SocketResponse, error) {
	return nil, nil
}
