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
		return nil, fmt.Errorf(
			"open database: %w",
			err,
		)
	}

	db.SetMaxOpenConns(1)

	d := &Database{
		DB: db,
	}

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

	/*
		The legacy peers table may exist in databases created by
		earlier versions. It is intentionally not used anymore because
		it permanently associates public keys with network addresses.

		We preserve it for compatibility rather than silently deleting
		user data during startup.
	*/

	CREATE TABLE IF NOT EXISTS peer_identities (
		namespace TEXT NOT NULL,
		public_key BLOB NOT NULL,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		PRIMARY KEY(namespace, public_key)
	);

	CREATE INDEX IF NOT EXISTS
		idx_peer_identities_public_key
	ON peer_identities(public_key);
	`

	if _, err := d.DB.Exec(schema); err != nil {
		return fmt.Errorf(
			"initialise database: %w",
			err,
		)
	}

	return nil
}

func (d *Database) SetMeta(
	key string,
	value string,
) error {
	_, err := d.DB.Exec(`
		INSERT INTO node_meta(key, value)
		VALUES (?, ?)
		ON CONFLICT(key)
		DO UPDATE SET value = excluded.value
	`,
		key,
		value,
	)

	if err != nil {
		return fmt.Errorf(
			"set metadata %q: %w",
			key,
			err,
		)
	}

	return nil
}

func (d *Database) GetMeta(
	key string,
) (string, error) {
	var value string

	err := d.DB.QueryRow(`
		SELECT value
		FROM node_meta
		WHERE key = ?
	`,
		key,
	).Scan(&value)

	if err != nil {
		return "", err
	}

	return value, nil
}

func (d *Database) RecordPeerIdentity(
	namespace string,
	publicKey []byte,
) error {
	now := time.Now().Unix()

	_, err := d.DB.Exec(`
		INSERT INTO peer_identities(
			namespace,
			public_key,
			first_seen,
			last_seen
		)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(namespace, public_key)
		DO UPDATE SET
			last_seen = excluded.last_seen
	`,
		namespace,
		publicKey,
		now,
		now,
	)

	if err != nil {
		return fmt.Errorf(
			"record peer identity: %w",
			err,
		)
	}

	return nil
}
