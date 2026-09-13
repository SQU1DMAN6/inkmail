package database

import (
	"database/sql"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/SQU1DMAN6/inkmail/internal/message"
)

type Database struct {
	DB *sql.DB
}

type StoredMessage struct {
	Message   message.Message
	Direction string
	Status    string
	StoredAt  int64
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

	CREATE TABLE IF NOT EXISTS messages (
		id TEXT PRIMARY KEY,
		sender_namespace TEXT NOT NULL,
		sender_public_key BLOB NOT NULL,
		recipient_namespace TEXT NOT NULL,
		recipient_public_key BLOB NOT NULL,
		subject TEXT NOT NULL,
		body TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		signature BLOB NOT NULL,
		direction TEXT NOT NULL,
		status TEXT NOT NULL,
		stored_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS
		idx_messages_created_at
	ON messages(created_at DESC);

	CREATE INDEX IF NOT EXISTS
		idx_messages_direction
	ON messages(direction);
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

func (d *Database) StoreMessage(
	msg *message.Message,
	direction string,
	status string,
) error {
	if msg == nil {
		return fmt.Errorf(
			"message cannot be nil",
		)
	}

	now := time.Now().Unix()

	senderKey, err := msg.SenderKey()
	if err != nil {
		return err
	}

	recipientKey, err := msg.RecipientKey()
	if err != nil {
		return err
	}

	signature := make([]byte, 0)

	if msg.Signature != "" {
		signature, err = decodeHex(msg.Signature)
		if err != nil {
			return fmt.Errorf(
				"decode message signature: %w",
				err,
			)
		}
	}

	_, err = d.DB.Exec(`
		INSERT INTO messages(
			id,
			sender_namespace,
			sender_public_key,
			recipient_namespace,
			recipient_public_key,
			subject,
			body,
			created_at,
			signature,
			direction,
			status,
			stored_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id)
		DO UPDATE SET
			status = excluded.status
	`,
		msg.ID,
		msg.SenderNamespace,
		[]byte(senderKey),
		msg.RecipientNamespace,
		[]byte(recipientKey),
		msg.Subject,
		msg.Body,
		msg.CreatedAt,
		signature,
		direction,
		status,
		now,
	)

	if err != nil {
		return fmt.Errorf(
			"store message: %w",
			err,
		)
	}

	return nil
}

func (d *Database) UpdateMessageStatus(
	id string,
	status string,
) error {
	result, err := d.DB.Exec(`
		UPDATE messages
		SET status = ?
		WHERE id = ?
	`,
		status,
		id,
	)

	if err != nil {
		return fmt.Errorf(
			"update message status: %w",
			err,
		)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return fmt.Errorf(
			"message %q not found",
			id,
		)
	}

	return nil
}

func (d *Database) ListMessages() ([]StoredMessage, error) {
	rows, err := d.DB.Query(`
		SELECT
			id,
			sender_namespace,
			sender_public_key,
			recipient_namespace,
			recipient_public_key,
			subject,
			body,
			created_at,
			signature,
			direction,
			status,
			stored_at
		FROM messages
		ORDER BY created_at DESC
	`)

	if err != nil {
		return nil, fmt.Errorf(
			"list messages: %w",
			err,
		)
	}

	defer rows.Close()

	var messages []StoredMessage

	for rows.Next() {
		stored, err := scanMessage(rows)
		if err != nil {
			return nil, err
		}

		messages = append(
			messages,
			stored,
		)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return messages, nil
}

func (d *Database) GetMessage(
	id string,
) (*StoredMessage, error) {
	row := d.DB.QueryRow(`
		SELECT
			id,
			sender_namespace,
			sender_public_key,
			recipient_namespace,
			recipient_public_key,
			subject,
			body,
			created_at,
			signature,
			direction,
			status,
			stored_at
		FROM messages
		WHERE id = ?
	`,
		id,
	)

	stored, err := scanMessageRow(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf(
				"message %q not found",
				id,
			)
		}

		return nil, err
	}

	return &stored, nil
}

func scanMessage(
	rows *sql.Rows,
) (StoredMessage, error) {
	var (
		stored       StoredMessage
		senderKey    []byte
		recipientKey []byte
		signature    []byte
	)

	err := rows.Scan(
		&stored.Message.ID,
		&stored.Message.SenderNamespace,
		&senderKey,
		&stored.Message.RecipientNamespace,
		&recipientKey,
		&stored.Message.Subject,
		&stored.Message.Body,
		&stored.Message.CreatedAt,
		&signature,
		&stored.Direction,
		&stored.Status,
		&stored.StoredAt,
	)

	if err != nil {
		return StoredMessage{}, err
	}

	stored.Message.SenderPublicKey =
		encodeHex(senderKey)

	stored.Message.RecipientPublicKey =
		encodeHex(recipientKey)

	stored.Message.Signature =
		encodeHex(signature)

	return stored, nil
}

func scanMessageRow(
	row *sql.Row,
) (StoredMessage, error) {
	var (
		stored       StoredMessage
		senderKey    []byte
		recipientKey []byte
		signature    []byte
	)

	err := row.Scan(
		&stored.Message.ID,
		&stored.Message.SenderNamespace,
		&senderKey,
		&stored.Message.RecipientNamespace,
		&recipientKey,
		&stored.Message.Subject,
		&stored.Message.Body,
		&stored.Message.CreatedAt,
		&signature,
		&stored.Direction,
		&stored.Status,
		&stored.StoredAt,
	)

	if err != nil {
		return StoredMessage{}, err
	}

	stored.Message.SenderPublicKey =
		encodeHex(senderKey)

	stored.Message.RecipientPublicKey =
		encodeHex(recipientKey)

	stored.Message.Signature =
		encodeHex(signature)

	return stored, nil
}

func encodeHex(value []byte) string {
	const hexChars = "0123456789abcdef"

	output := make(
		[]byte,
		len(value)*2,
	)

	for i, b := range value {
		output[i*2] = hexChars[b>>4]
		output[i*2+1] = hexChars[b&0x0f]
	}

	return string(output)
}

func decodeHex(value string) ([]byte, error) {
	if len(value)%2 != 0 {
		return nil, fmt.Errorf(
			"invalid hexadecimal value",
		)
	}

	output := make(
		[]byte,
		len(value)/2,
	)

	for i := range output {
		high, ok := hexDigit(value[i*2])
		if !ok {
			return nil, fmt.Errorf(
				"invalid hexadecimal value",
			)
		}

		low, ok := hexDigit(value[i*2+1])
		if !ok {
			return nil, fmt.Errorf(
				"invalid hexadecimal value",
			)
		}

		output[i] = high<<4 | low
	}

	return output, nil
}

func hexDigit(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}
