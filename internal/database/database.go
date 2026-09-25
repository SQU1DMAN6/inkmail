package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/SQU1DMAN6/inkmail/internal/message"
)

// MailboxOpKind enumerates the signed mailbox mutations a device may issue
// for one of its own messages. Ops are replicated to Daddy so every device
// converges, but only the message owner may author them.
const (
	MailboxOpMove   = "move"
	MailboxOpDelete = "delete"
)

// Reserved mailbox folders. "inbox" is the default view; "archive" and
// "important" are the built-in user folders. Custom folder names are allowed
// but validated by NormaliseFolder.
const (
	FolderInbox     = "inbox"
	FolderArchive   = "archive"
	FolderImportant = "important"
	FolderDeleted   = "deleted"
)

// MailboxOp is one signed move/delete mutation for a single message.
type MailboxOp struct {
	MessageID   string
	Op          string
	Folder      string
	AuthorNS    string
	AuthorKey   []byte
	Timestamp   int64
	Signature   []byte
	SubmittedAt int64
}

type Database struct {
	DB *sql.DB
}

type StoredMessage struct {
	Message   message.Message
	Direction string
	Status    string
	StoredAt  int64
}

// Canonical message directions (SPEC v0.5 sections 4, 5, 13, 14).
//
//   - DirectionSent: the message left this device and InkMail has accepted
//     responsibility for delivering it (direct ACK or HOLD_ACK).
//   - DirectionQueued: the message exists locally but has not yet been
//     transferred to any relay or destination. It must be retried.
//   - DirectionReceived: an envelope addressed to this device was
//     authenticated, decrypted and committed to the local store.
//
// The legacy "in" direction (pre-v0.5 inbound label) is migrated to
// "received" on open, and "out" is migrated to "sent". The two must never
// coexist as user-facing types.
const (
	DirectionSent     = "sent"
	DirectionQueued   = "queued"
	DirectionReceived = "received"
)

// Legacy directions rewritten by the migration below.
const (
	legacyDirectionIn  = "in"
	legacyDirectionOut = "out"
)

// Unknown values are returned unchanged so future states keep working.
func NormaliseDirection(direction string) string {
	switch direction {
	case legacyDirectionIn:
		return DirectionReceived
	case legacyDirectionOut:
		return DirectionSent
	default:
		return direction
	}
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
		encryption_public_key BLOB,
		alias TEXT NOT NULL DEFAULT '',
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		PRIMARY KEY(namespace, public_key)
	);

	CREATE INDEX IF NOT EXISTS
		idx_peer_identities_public_key
	ON peer_identities(public_key);

	CREATE UNIQUE INDEX IF NOT EXISTS
		idx_peer_identities_alias
	ON peer_identities(alias COLLATE NOCASE)
	WHERE alias != '';

	CREATE TABLE IF NOT EXISTS peer_routes (
		namespace TEXT NOT NULL,
		public_key BLOB NOT NULL,
		address TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		last_seen INTEGER NOT NULL,
		PRIMARY KEY(namespace, public_key, address)
	);

	CREATE INDEX IF NOT EXISTS
		idx_peer_routes_expiry
	ON peer_routes(expires_at);

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
		folder TEXT NOT NULL DEFAULT 'inbox',
		folder_updated_at INTEGER NOT NULL DEFAULT 0,
		stored_at INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS mailbox_ops (
		message_id TEXT NOT NULL,
		op TEXT NOT NULL,
		folder TEXT NOT NULL DEFAULT '',
		author_namespace TEXT NOT NULL,
		author_public_key BLOB NOT NULL,
		timestamp INTEGER NOT NULL,
		signature BLOB NOT NULL,
		submitted_at INTEGER NOT NULL,
		PRIMARY KEY(message_id, op, timestamp, author_public_key)
	);

	CREATE INDEX IF NOT EXISTS
		idx_mailbox_ops_message
	ON mailbox_ops(message_id);

	CREATE INDEX IF NOT EXISTS
		idx_messages_created_at
	ON messages(created_at DESC);

	CREATE INDEX IF NOT EXISTS
		idx_messages_direction
	ON messages(direction);

	CREATE TABLE IF NOT EXISTS held_messages (
		id TEXT PRIMARY KEY,
		sender_namespace TEXT NOT NULL,
		sender_public_key BLOB NOT NULL,
		recipient_namespace TEXT NOT NULL,
		recipient_public_key BLOB NOT NULL,
		payload BLOB NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL,
		stored_at INTEGER NOT NULL
	);

	CREATE INDEX IF NOT EXISTS
		idx_held_messages_expires_at
	ON held_messages(expires_at);
	`

	if _, err := d.DB.Exec(schema); err != nil {
		return fmt.Errorf(
			"initialise database: %w",
			err,
		)
	}

	if err := d.migrate(); err != nil {
		return err
	}

	return nil
}

// migrate applies additive schema upgrades to databases created by
// earlier InkMail releases. All migrations must be idempotent.
func (d *Database) migrate() error {
	migrations := []string{
		`ALTER TABLE peer_identities
		 ADD COLUMN encryption_public_key BLOB`,
		`ALTER TABLE peer_identities
		 ADD COLUMN alias TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE messages
		 ADD COLUMN folder TEXT NOT NULL DEFAULT 'inbox'`,
		`ALTER TABLE messages
		 ADD COLUMN folder_updated_at INTEGER NOT NULL DEFAULT 0`,
	}

	for _, statement := range migrations {
		if _, err := d.DB.Exec(statement); err != nil {
			if isDuplicateColumnError(err) {
				continue
			}

			return fmt.Errorf(
				"apply migration: %w",
				err,
			)
		}
	}

	// Case-insensitive alias uniqueness for databases created before the
	// partial unique index existed. The CREATE in init() covers fresh DBs;
	// this covers upgraded DBs. Best-effort: a pre-existing duplicate keeps
	// the DB usable and SetPeerAlias enforces uniqueness going forward.
	if _, err := d.DB.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS
		idx_peer_identities_alias
	ON peer_identities(alias COLLATE NOCASE)
	WHERE alias != ''`); err != nil {
		return fmt.Errorf("apply alias index migration: %w", err)
	}

	// Normalise legacy alias values: trim whitespace, drop empties to ''.
	if _, err := d.DB.Exec(`UPDATE peer_identities SET alias = '' WHERE TRIM(alias) = ''`); err != nil {
		return fmt.Errorf("normalise peer aliases: %w", err)
	}

	// SPEC v0.5 section 13: the user-visible "in" direction becomes
	// "received"; the legacy "out" direction becomes "sent".
	if _, err := d.DB.Exec(
		`UPDATE messages SET direction = ? WHERE direction = ?`,
		DirectionReceived,
		legacyDirectionIn,
	); err != nil {
		return fmt.Errorf(
			"migrate message directions: %w",
			err,
		)
	}

	if _, err := d.DB.Exec(
		`UPDATE messages SET direction = ? WHERE direction = ?`,
		DirectionSent,
		legacyDirectionOut,
	); err != nil {
		return fmt.Errorf(
			"migrate message directions: %w",
			err,
		)
	}

	return nil
}

func isDuplicateColumnError(err error) bool {
	if err == nil {
		return false
	}

	message := err.Error()

	return strings.Contains(
		message,
		"duplicate column name",
	)
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

// RecordPeerIdentity stores or refreshes a known peer identity. The peer's
// X25519 encryption public key is optional; when supplied it is persisted so
// that end-to-end encrypted messages can later be addressed to the peer.
// The alias is preserved on refresh: handshake-driven updates must never wipe
// a user-assigned friendly name.
func (d *Database) RecordPeerIdentity(
	namespace string,
	publicKey []byte,
) error {
	return d.RecordPeerIdentityWithKey(
		namespace,
		publicKey,
		nil,
	)
}

// RecordPeerIdentityWithKey stores or refreshes a known peer identity together
// with the peer's published X25519 encryption public key.
func (d *Database) RecordPeerIdentityWithKey(
	namespace string,
	publicKey []byte,
	encryptionPublicKey []byte,
) error {
	now := time.Now().Unix()

	_, err := d.DB.Exec(`
		INSERT INTO peer_identities(
			namespace,
			public_key,
			encryption_public_key,
			alias,
			first_seen,
			last_seen
		)
		VALUES (?, ?, ?, '', ?, ?)
		ON CONFLICT(namespace, public_key)
		DO UPDATE SET
			encryption_public_key = COALESCE(
				excluded.encryption_public_key,
				peer_identities.encryption_public_key
			),
			last_seen = excluded.last_seen
	`,
		namespace,
		publicKey,
		encryptionPublicKey,
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

// ListPeerIdentities returns all known peer identities
// ordered by namespace, public_key for deterministic results
func (d *Database) ListPeerIdentities() ([]PeerIdentity, error) {
	rows, err := d.DB.Query(`
		SELECT
			namespace,
			public_key,
			encryption_public_key,
			alias,
			first_seen,
			last_seen
		FROM peer_identities
		ORDER BY namespace, public_key
	`)
	if err != nil {
		return nil, fmt.Errorf("list peer identities: %w", err)
	}
	defer rows.Close()

	peers := make([]PeerIdentity, 0)

	for rows.Next() {
		var (
			peer          PeerIdentity
			encryptionKey []byte
		)

		if err := rows.Scan(
			&peer.Namespace,
			&peer.PublicKey,
			&encryptionKey,
			&peer.Alias,
			&peer.FirstSeen,
			&peer.LastSeen,
		); err != nil {
			return nil, fmt.Errorf("scan peer identity: %w", err)
		}

		peer.EncryptionPublicKey = encryptionKey

		peers = append(peers, peer)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return peers, nil
}

// GetPeerIdentity returns a single known peer identity by namespace and
// Ed25519 public key.
func (d *Database) GetPeerIdentity(
	namespace string,
	publicKey []byte,
) (*PeerIdentity, error) {
	peers, err := d.ListPeerIdentities()
	if err != nil {
		return nil, err
	}

	for i := range peers {
		if peers[i].Namespace != namespace {
			continue
		}

		if !bytesEqual(
			peers[i].PublicKey,
			publicKey,
		) {
			continue
		}

		return &peers[i], nil
	}

	return nil, fmt.Errorf(
		"peer identity not found",
	)
}

func bytesEqual(
	a []byte,
	b []byte,
) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

// PeerIdentity represents a known peer identity
type PeerIdentity struct {
	Namespace           string
	PublicKey           []byte
	EncryptionPublicKey []byte
	Alias               string
	FirstSeen           int64
	LastSeen            int64
}

// StoreMessage persists a message idempotently. A repeated delivery of an
// already-stored ID keeps the original direction and only refreshes the
// status, so duplicate delivery can never create a second user-visible copy
// (SPEC v0.5 Test H).
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
			folder,
			folder_updated_at,
			stored_at
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
		FolderInbox,
		now,
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

// NormaliseFolder lowercases, trims and validates a mailbox folder name.
// Empty means the default inbox view. Reserved names inbox/archive/important/
// deleted are always accepted; custom names must be 1-64 chars of
// letters/digits/dash/underscore/dot.
func NormaliseFolder(folder string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(folder))
	if name == "" {
		return FolderInbox, nil
	}
	switch name {
	case FolderInbox, FolderArchive, FolderImportant, FolderDeleted:
		return name, nil
	}
	if len(name) > 64 {
		return "", fmt.Errorf("folder name too long")
	}
	for _, r := range name {
		ok := r >= 'a' && r <= 'z' || r >= '0' && r <= '9' ||
			r == '-' || r == '_' || r == '.'
		if !ok {
			return "", fmt.Errorf("invalid folder name %q", folder)
		}
	}
	return name, nil
}

// ListMessagesInFolder returns stored messages filtered by folder.
// Empty folder selects the default inbox view; "all" returns everything.
func (d *Database) ListMessagesInFolder(folder string) ([]StoredMessage, error) {
	name := strings.ToLower(strings.TrimSpace(folder))
	if name == "" {
		name = FolderInbox
	}
	var rows *sql.Rows
	var err error
	if name == "all" {
		rows, err = d.DB.Query(`
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
				folder,
				folder_updated_at,
				stored_at
			FROM messages
			ORDER BY stored_at DESC
		`)
	} else {
		rows, err = d.DB.Query(`
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
				folder,
				folder_updated_at,
				stored_at
			FROM messages
			WHERE folder = ?
			ORDER BY stored_at DESC
		`, name)
	}
	if err != nil {
		return nil, fmt.Errorf("list messages: %w", err)
	}
	defer rows.Close()
	var out []StoredMessage
	for rows.Next() {
		var stored StoredMessage
		var signature []byte
		var senderKey, recipientKey []byte
		var folder string
		var folderUpdated int64
		if err := rows.Scan(
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
			&folder,
			&folderUpdated,
			&stored.StoredAt,
		); err != nil {
			return nil, fmt.Errorf("scan message row: %w", err)
		}
		stored.Message.SenderPublicKey = encodeHex(senderKey)
		stored.Message.RecipientPublicKey = encodeHex(recipientKey)
		stored.Message.Signature = encodeHex(signature)
		stored.Direction = NormaliseDirection(stored.Direction)
		_ = folder
		_ = folderUpdated
		out = append(out, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}
	return out, nil
}

// ApplyMailboxOp records a signed op and applies last-writer-wins folder
// state for the message when the op timestamp is newer than current state.
// Unknown message IDs are still journalled so late-arriving envelopes
// converge when they appear. Returns true when local folder state changed.
func (d *Database) ApplyMailboxOp(op MailboxOp) (bool, error) {
	if strings.TrimSpace(op.MessageID) == "" {
		return false, fmt.Errorf("mailbox op has no message id")
	}
	if op.Op != MailboxOpMove && op.Op != MailboxOpDelete {
		return false, fmt.Errorf("unknown mailbox op %q", op.Op)
	}
	folder := FolderDeleted
	if op.Op == MailboxOpMove {
		normalised, err := NormaliseFolder(op.Folder)
		if err != nil {
			return false, err
		}
		folder = normalised
	}
	now := time.Now().Unix()
	if _, err := d.DB.Exec(`
		INSERT INTO mailbox_ops(
			message_id, op, folder,
			author_namespace, author_public_key,
			timestamp, signature, submitted_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(message_id, op, timestamp, author_public_key)
		DO NOTHING
	`, op.MessageID, op.Op, folder, op.AuthorNS, op.AuthorKey,
		op.Timestamp, op.Signature, now); err != nil {
		return false, fmt.Errorf("record mailbox op: %w", err)
	}
	res, err := d.DB.Exec(`
		UPDATE messages SET folder = ?, folder_updated_at = ?
		WHERE id = ? AND folder_updated_at < ?
	`, folder, op.Timestamp, op.MessageID, op.Timestamp)
	if err != nil {
		return false, fmt.Errorf("apply mailbox op: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("mailbox op rows: %w", err)
	}
	return affected > 0, nil
}

// ListMailboxOpsSince returns ops journalled after the given rowid watermark.
func (d *Database) ListMailboxOpsSince(since int64, limit int) ([]MailboxOp, int64, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.DB.Query(`
		SELECT rowid, message_id, op, folder,
			author_namespace, author_public_key,
			timestamp, signature, submitted_at
		FROM mailbox_ops
		WHERE rowid > ?
		ORDER BY rowid ASC
		LIMIT ?
	`, since, limit)
	if err != nil {
		return nil, since, fmt.Errorf("list mailbox ops: %w", err)
	}
	defer rows.Close()
	var ops []MailboxOp
	watermark := since
	for rows.Next() {
		var op MailboxOp
		var rowid int64
		if err := rows.Scan(&rowid, &op.MessageID, &op.Op, &op.Folder,
			&op.AuthorNS, &op.AuthorKey, &op.Timestamp, &op.Signature,
			&op.SubmittedAt); err != nil {
			return nil, since, fmt.Errorf("scan mailbox op: %w", err)
		}
		ops = append(ops, op)
		watermark = rowid
	}
	if err := rows.Err(); err != nil {
		return nil, since, fmt.Errorf("iterate mailbox ops: %w", err)
	}
	return ops, watermark, nil
}

// GetMessageFolder returns the current folder of a stored message.
func (d *Database) GetMessageFolder(id string) (string, error) {
	var folder string
	err := d.DB.QueryRow(`SELECT folder FROM messages WHERE id = ?`, id).Scan(&folder)
	if err != nil {
		return "", err
	}
	return folder, nil
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

// HeldMessage represents a message stored for hold-and-forward delivery
type HeldMessage struct {
	ID                 string
	SenderNamespace    string
	SenderPublicKey    []byte
	RecipientNamespace string
	RecipientPublicKey []byte
	Payload            []byte
	CreatedAt          int64
	ExpiresAt          int64
	StoredAt           int64
}

// StoreHeldMessage stores an encrypted message for hold-and-forward delivery
func (d *Database) StoreHeldMessage(id string, senderNamespace string, senderPublicKey []byte,
	recipientNamespace string, recipientPublicKey []byte, payload []byte,
	createdAt int64, expiresAt int64) error {
	_, err := d.DB.Exec(`
		INSERT INTO held_messages(id, sender_namespace, sender_public_key,
			recipient_namespace, recipient_public_key, payload, created_at, expires_at, stored_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`, id, senderNamespace, senderPublicKey, recipientNamespace, recipientPublicKey,
		payload, createdAt, expiresAt, time.Now().Unix())

	if err != nil {
		return fmt.Errorf("store held message: %w", err)
	}

	return nil
}

// GetHeldMessagesForRecipient retrieves all held messages for a specific recipient
func (d *Database) GetHeldMessagesForRecipient(recipientPublicKey []byte) ([]HeldMessage, error) {
	rows, err := d.DB.Query(`
		SELECT id, sender_namespace, sender_public_key, recipient_namespace,
		       recipient_public_key, payload, created_at, expires_at, stored_at
		FROM held_messages
		WHERE recipient_public_key = ?
		ORDER BY created_at ASC
	`, recipientPublicKey)
	if err != nil {
		return nil, fmt.Errorf("query held messages: %w", err)
	}
	defer rows.Close()

	var messages []HeldMessage
	for rows.Next() {
		var hm HeldMessage
		err := rows.Scan(&hm.ID, &hm.SenderNamespace, &hm.SenderPublicKey,
			&hm.RecipientNamespace, &hm.RecipientPublicKey, &hm.Payload,
			&hm.CreatedAt, &hm.ExpiresAt, &hm.StoredAt)
		if err != nil {
			return nil, fmt.Errorf("scan held message: %w", err)
		}
		messages = append(messages, hm)
	}

	return messages, rows.Err()
}

// DeleteHeldMessage removes a held message after successful delivery
func (d *Database) DeleteHeldMessage(id string) error {
	_, err := d.DB.Exec(`
		DELETE FROM held_messages WHERE id = ?
	`, id)
	if err != nil {
		return fmt.Errorf("delete held message: %w", err)
	}
	return nil
}

// DeleteExpiredHeldMessages removes held messages that have expired (30-day TTL)
func (d *Database) DeleteExpiredHeldMessages() error {
	_, err := d.DB.Exec(`
		DELETE FROM held_messages
		WHERE expires_at <= ?
	`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("delete expired held messages: %w", err)
	}
	return nil
}

// CountHeldMessages returns the number of held messages in the database
func (d *Database) CountHeldMessages() (int, error) {
	var count int
	err := d.DB.QueryRow(`
		SELECT COUNT(*) FROM held_messages
	`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count held messages: %w", err)
	}
	return count, nil
}

// HeldMessageExists reports whether a held message with the given ID is
// already stored. It is used to make hold-and-forward delivery idempotent.
func (d *Database) HeldMessageExists(id string) (bool, error) {
	var count int

	err := d.DB.QueryRow(`
		SELECT COUNT(*) FROM held_messages WHERE id = ?
	`, id).Scan(&count)
	if err != nil {
		return false, fmt.Errorf(
			"check held message: %w",
			err,
		)
	}

	return count > 0, nil
}

// GetHeldMessage retrieves a single held message by ID.
func (d *Database) GetHeldMessage(id string) (*HeldMessage, error) {
	row := d.DB.QueryRow(`
		SELECT
			id,
			sender_namespace,
			sender_public_key,
			recipient_namespace,
			recipient_public_key,
			payload,
			created_at,
			expires_at,
			stored_at
		FROM held_messages
		WHERE id = ?
	`, id)

	var hm HeldMessage

	err := row.Scan(
		&hm.ID,
		&hm.SenderNamespace,
		&hm.SenderPublicKey,
		&hm.RecipientNamespace,
		&hm.RecipientPublicKey,
		&hm.Payload,
		&hm.CreatedAt,
		&hm.ExpiresAt,
		&hm.StoredAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf(
				"held message %q not found",
				id,
			)
		}

		return nil, fmt.Errorf(
			"get held message: %w",
			err,
		)
	}

	return &hm, nil
}

// Route is a temporary, expiring description of how a peer can be reached.
type Route struct {
	Namespace string
	PublicKey []byte
	Address   string
	ExpiresAt int64
	LastSeen  int64
}

// StoreRoute records or refreshes a temporary route to a peer.
func (d *Database) StoreRoute(
	namespace string,
	publicKey []byte,
	address string,
	expiresAt int64,
) error {
	now := time.Now().Unix()

	_, err := d.DB.Exec(`
		INSERT INTO peer_routes(
			namespace,
			public_key,
			address,
			expires_at,
			last_seen
		)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(namespace, public_key, address)
		DO UPDATE SET
			expires_at = excluded.expires_at,
			last_seen = excluded.last_seen
	`,
		namespace,
		publicKey,
		address,
		expiresAt,
		now,
	)
	if err != nil {
		return fmt.Errorf(
			"store peer route: %w",
			err,
		)
	}

	return nil
}

// GetRoute returns the newest unexpired route for a peer, or an error when
// no usable route is available.
func (d *Database) GetRoute(
	namespace string,
	publicKey []byte,
) (*Route, error) {
	routes, err := d.ListRoutes(
		namespace,
		publicKey,
	)
	if err != nil {
		return nil, err
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf(
			"no route for %s",
			namespace,
		)
	}

	return &routes[0], nil
}

// ListRoutes returns all unexpired routes for a peer ordered by expiry, so
// that the freshest route is returned first.
func (d *Database) ListRoutes(
	namespace string,
	publicKey []byte,
) ([]Route, error) {
	now := time.Now().Unix()

	rows, err := d.DB.Query(`
		SELECT
			namespace,
			public_key,
			address,
			expires_at,
			last_seen
		FROM peer_routes
		WHERE namespace = ?
		  AND public_key = ?
		  AND expires_at > ?
		ORDER BY expires_at DESC, last_seen DESC
	`,
		namespace,
		publicKey,
		now,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"list peer routes: %w",
			err,
		)
	}
	defer rows.Close()

	routes := make([]Route, 0)

	for rows.Next() {
		var route Route

		if err := rows.Scan(
			&route.Namespace,
			&route.PublicKey,
			&route.Address,
			&route.ExpiresAt,
			&route.LastSeen,
		); err != nil {
			return nil, fmt.Errorf(
				"scan peer route: %w",
				err,
			)
		}

		routes = append(routes, route)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return routes, nil
}

// DeleteExpiredRoutes removes routes whose expiry has passed.
func (d *Database) DeleteExpiredRoutes() error {
	_, err := d.DB.Exec(`
		DELETE FROM peer_routes
		WHERE expires_at <= ?
	`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf(
			"delete expired routes: %w",
			err,
		)
	}

	return nil
}

// RegisterOrReplaceRoute records a route for a peer while superseding every
// stale route the peer previously advertised (SPEC v0.5 section 28, Test I).
//
// A new registration at route B replaces route A instead of accumulating
// alongside it. Both client and Daddy caches call this after a registration
// or a successful lookup, so the active set only ever holds the freshest
// known address.
func (d *Database) RegisterOrReplaceRoute(
	namespace string,
	publicKey []byte,
	address string,
	expiresAt int64,
) error {
	now := time.Now().Unix()

	tx, err := d.DB.Begin()
	if err != nil {
		return fmt.Errorf(
			"begin route registration: %w",
			err,
		)
	}

	committed := false

	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.Exec(
		`DELETE FROM peer_routes
		 WHERE namespace = ?
		   AND public_key = ?
		   AND address != ?`,
		namespace,
		publicKey,
		address,
	); err != nil {
		return fmt.Errorf(
			"supersede stale peer routes: %w",
			err,
		)
	}

	if _, err := tx.Exec(
		`INSERT INTO peer_routes(
			namespace,
			public_key,
			address,
			expires_at,
			last_seen
		)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(namespace, public_key, address)
		DO UPDATE SET
			expires_at = excluded.expires_at,
			last_seen = excluded.last_seen`,
		namespace,
		publicKey,
		address,
		expiresAt,
		now,
	); err != nil {
		return fmt.Errorf(
			"store peer route: %w",
			err,
		)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf(
			"commit route registration: %w",
			err,
		)
	}

	committed = true

	return nil
}

// DeleteRoute removes one specific route. It is used to drop a route that
// has just proven unreachable, so the next send does not retry the same
// dead address (SPEC v0.5 section 17).
func (d *Database) DeleteRoute(
	namespace string,
	publicKey []byte,
	address string,
) error {
	_, err := d.DB.Exec(
		`DELETE FROM peer_routes
		 WHERE namespace = ?
		   AND public_key = ?
		   AND address = ?`,
		namespace,
		publicKey,
		address,
	)
	if err != nil {
		return fmt.Errorf(
			"delete peer route: %w",
			err,
		)
	}

	return nil
}

// DeleteAllRoutesForPeer removes every route advertised by a peer. This is
// used when a peer is no longer reachable at previously recorded addresses.
func (d *Database) DeleteAllRoutesForPeer(
	namespace string,
	publicKey []byte,
) error {
	_, err := d.DB.Exec(`
		DELETE FROM peer_routes
		WHERE namespace = ?
		  AND public_key = ?
	`, namespace, publicKey)
	if err != nil {
		return fmt.Errorf(
			"delete peer routes: %w",
			err,
		)
	}

	return nil
}
