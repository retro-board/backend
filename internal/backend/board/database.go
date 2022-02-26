package board

import (
	"fmt"
	"net/url"

	bugLog "github.com/bugfixes/go-bugfixes/logs"
	"github.com/jackc/pgx/v4"
)

func (b *Board) getConnection() (*pgx.Conn, error) {
	conn, err := pgx.Connect(b.CTX, fmt.Sprintf(
		"postgresql://%s:%s@%s:%d/%s",
		b.Config.RDS.User,
		b.Config.RDS.Password,
		b.Config.RDS.Host,
		b.Config.RDS.Port,
		b.Config.RDS.DBName))
	if err != nil {
		return nil, bugLog.Error(err)
	}

	return conn, nil
}

func (b *Board) GetAllBoards(subDomain string) ([]BoardInfo, error) {
	var boards []BoardInfo
	conn, err := b.getConnection()
	if err != nil {
		return boards, bugLog.Error(err)
	}
	defer func() {
		if err := conn.Close(b.CTX); err != nil {
			bugLog.Debugf("getAllBoards: %+v", err)
		}
	}()

	rows, err := conn.Query(b.CTX,
		`SELECT id, name, retros_completed, team_score, team_previous_score
		FROM board
		WHERE company_id = (SELECT id FROM company WHERE subdomain = $1)`,
		subDomain)
	if err != nil {
		return boards, bugLog.Error(err)
	}

	for rows.Next() {
		var board BoardInfo
		if err := rows.Scan(
			&board.ID,
			&board.Name,
			&board.RetrosCompleted,
			&board.TeamScore,
			&board.PreviousScore); err != nil {
			return boards, bugLog.Error(err)
		}
		boards = append(boards, board)
	}

	// safe link the name
	for i := range boards {
		boards[i].LinkName = url.QueryEscape(boards[i].Name)
	}

	return boards, nil
}
