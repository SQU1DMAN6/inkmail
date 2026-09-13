package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

type Database struct {
	DB *sql.DB
}

func Open(path string) (*Database, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	db.SetMaxOpenConns(1)

	d := &Database{DB: db}

	if err := d.init(); err != nil {
		db.Close()
		return nil, err
	}

	return d, nil
}

func (d *Database) init() error {
	schema := `
	PRAGMA journal_mode = WAL;
	PRAGMA foreign_keys = ON;

	CREATE TABLE IF NOT EXISTS node_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS peers (
		public_key BLOB PRIMARY KEY,
		address TEXT NOT NULL,
		last_seen INTEGER NOT NULL
	);
	`

	if _, err := d.DB.Exec(schema); err != nil {
		return fmt.Errorf("initialise database: %w", err)
	}

	return nil
}

func (d *Database) UpsertPeer(publicKey []byte, address string) error {
	_, err := d.DB.Exec(`
		INSERT INTO peers(public_key, address, last_seen)
		VALUES (?, ?, ?)
		ON CONFLICT(public_key)
		DO UPDATE SET
			address = excluded.address,
			last_seen = excluded.last_seen
	`,
		publicKey,
		address,
		time.Now().Unix(),
	)

	return err
}
