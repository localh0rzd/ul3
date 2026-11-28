package main

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
)

// The schema is intentionally identical to ul2's inc/uploads.db so an old
// database can be mounted as-is. Note: the "ip" column holds the uploader's
// browser UUID (it was named "ip" historically).
const schema = `
CREATE TABLE IF NOT EXISTS "cron" (
	"datetime" DATETIME NOT NULL,
	numdeleted INT NOT NULL,
	errors INT NOT NULL
);
CREATE TABLE IF NOT EXISTS "uploads" (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL,
	"datetime" DATETIME NOT NULL,
	filename TEXT NOT NULL,
	crc32 INT,
	deleted INT DEFAULT 0
);
CREATE INDEX IF NOT EXISTS uploads_owner ON uploads(ip, deleted);
CREATE INDEX IF NOT EXISTS uploads_datetime ON uploads("datetime");
`

type store struct{ db *sql.DB }

type upload struct {
	ID       int64  `json:"id"`
	Owner    string `json:"owner,omitempty"`
	Time     int64  `json:"time"`
	Filename string `json:"filename"`
	CRC32    uint32 `json:"crc32"`
	Deleted  bool   `json:"deleted"`
	URL      string `json:"url,omitempty"`
	Size     int64  `json:"size"`
	Inline   bool   `json:"inline"`
}

type cronStatus struct {
	Time       int64 `json:"time"`
	NumDeleted int64 `json:"numDeleted"`
	Errors     int64 `json:"errors"`
}

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite: serialise access, avoids SQLITE_BUSY entirely
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func (s *store) Close() error { return s.db.Close() }

func (s *store) Insert(ctx context.Context, owner, filename string, crc uint32, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO uploads (ip, "datetime", filename, crc32, deleted) VALUES (?, ?, ?, ?, 0)`,
		owner, t.Unix(), filename, int64(crc))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *store) ListByOwner(ctx context.Context, owner string) ([]upload, error) {
	return s.query(ctx, `SELECT id, ip, "datetime", filename, COALESCE(crc32,0), COALESCE(deleted,0)
		FROM uploads WHERE ip = ? AND deleted = 0 ORDER BY "datetime" DESC, id DESC LIMIT 1000`, owner)
}

func (s *store) ListAll(ctx context.Context) ([]upload, error) {
	return s.query(ctx, `SELECT id, ip, "datetime", filename, COALESCE(crc32,0), COALESCE(deleted,0)
		FROM uploads ORDER BY id DESC LIMIT 5000`)
}

func (s *store) query(ctx context.Context, q string, args ...any) ([]upload, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []upload{}
	for rows.Next() {
		var u upload
		var crc, del int64
		if err := rows.Scan(&u.ID, &u.Owner, &u.Time, &u.Filename, &crc, &del); err != nil {
			return nil, err
		}
		u.CRC32, u.Deleted = uint32(crc), del != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// Get returns an active upload. When owner is non-nil it must match.
func (s *store) Get(ctx context.Context, id int64, owner *string) (upload, error) {
	q := `SELECT id, ip, "datetime", filename, COALESCE(crc32,0), COALESCE(deleted,0) FROM uploads WHERE id = ? AND deleted = 0`
	args := []any{id}
	if owner != nil {
		q += ` AND ip = ?`
		args = append(args, *owner)
	}
	list, err := s.query(ctx, q, args...)
	if err != nil {
		return upload{}, err
	}
	if len(list) == 0 {
		return upload{}, sql.ErrNoRows
	}
	return list[0], nil
}

func (s *store) MarkDeleted(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE uploads SET deleted = 1 WHERE id = ?`, id)
	return err
}

func (s *store) Expired(ctx context.Context, before time.Time) ([]upload, error) {
	return s.query(ctx, `SELECT id, ip, "datetime", filename, COALESCE(crc32,0), COALESCE(deleted,0)
		FROM uploads WHERE "datetime" < ?`, before.Unix())
}

func (s *store) Remove(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM uploads WHERE id = ?`, id)
	return err
}

func (s *store) SetCron(ctx context.Context, c cronStatus) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM cron`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO cron ("datetime", numdeleted, errors) VALUES (?, ?, ?)`,
		c.Time, c.NumDeleted, c.Errors); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *store) Cron(ctx context.Context) (*cronStatus, error) {
	var c cronStatus
	err := s.db.QueryRowContext(ctx, `SELECT CAST("datetime" AS INTEGER), numdeleted, errors FROM cron LIMIT 1`).
		Scan(&c.Time, &c.NumDeleted, &c.Errors)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &c, err
}
