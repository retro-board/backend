package ws

import (
	"context"
	"fmt"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/jackc/pgx/v4"
	"github.com/retro-board/backend/internal/config"
)

type Topic struct {
	Config *config.Config

	ClientID string
	BoardID  string
}

const (
	ResponseTopicCreated = 1
	ResponseTopicDeleted = 2

	ResponseTopicVoted   = 3
	ResponseTopicUnvoted = 4
)

type TopicCreate struct {
	Topic Topic

	Type    string `json:"type"`
	Content string `json:"content"`
	Column  int    `json:"column"`
}
type TopicDelete struct {
	Topic Topic

	Type    string `json:"type"`
	TopicID int    `json:"topic_id"`
}
type TopicVote struct {
	Topic Topic

	Type    string `json:"type"`
	TopicID int    `json:"topic_id"`
}

type TopicUnvote struct {
	Topic Topic

	Type    string `json:"type"`
	TopicID int    `json:"topic_id"`
}

func (t Topic) getConnection() (*pgx.Conn, error) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		t.Config.RDS.User,
		t.Config.RDS.Password,
		t.Config.RDS.Host,
		t.Config.RDS.Port,
		t.Config.RDS.DBName))
	if err != nil {
		return nil, bugLog.Error(err)
	}

	return conn, nil
}

func (t TopicCreate) Perform() (*SocketResponse, error) {
	type TopicCreated struct {
		TopicID string `json:"topic_id"`
		Content string `json:"content"`
		Column  int    `json:"column"`
	}

	conn, err := t.Topic.getConnection()
	if err != nil {
		return nil, bugLog.Error(err)
	}
	defer func() {
		if err := conn.Close(context.Background()); err != nil {
			bugLog.Debug(err)
		}
	}()

	var topicID int
	if err := conn.QueryRow(context.Background(), `
    INSERT INTO topic (board_id, client_id, content, "column")
    VALUES ($1, $2, $3, $4)
    RETURNING id`,
		t.Topic.BoardID,
		t.Topic.ClientID,
		t.Content,
		t.Column).Scan(&topicID); err != nil {
		return nil, bugLog.Error(err)
	}

	tc := TopicCreated{
		TopicID: fmt.Sprintf("%d", topicID),
		Column:  t.Column,
		Content: t.Content,
	}

	return &SocketResponse{
		Type: ResponseTopicCreated,
		Data: tc,
	}, nil
}

func (t TopicDelete) Perform() (*SocketResponse, error) {
	return nil, nil
}

func (t TopicVote) Perform() (*SocketResponse, error) {
	return nil, nil
}

func (t TopicUnvote) Perform() (*SocketResponse, error) {
	return nil, nil
}
