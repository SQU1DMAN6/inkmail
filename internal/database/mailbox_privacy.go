package database

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	MaxOpaqueEnvelopeSize   = 2 * 1024 * 1024
	MaxOpaqueDeliveryBytes  = 3 * 1024 * 1024
	maxHeldMessagesPerUser  = 256
	maxHeldBytesPerUser     = 32 * 1024 * 1024
	maxSeenEnvelopesPerUser = 4096
	maxEnvelopeRetention    = 30 * 24 * time.Hour
)

// OpaqueHeldMessage contains only the mailbox address, random envelope ID and
// encrypted bytes Daddy needs for temporary delivery.
type OpaqueHeldMessage struct {
	ID        string
	MailboxID string
	Payload   []byte
	ExpiresAt int64
	StoredAt  int64
}

type OpaqueOutboxMessage struct {
	ID        string
	MailboxID string
	Payload   []byte
	StoredAt  int64
}

// QueueOpaqueOutbox retains an encrypted envelope while Daddy relays are
// unavailable; it stores no user-visible message content or identity fields.
func (d *Database) QueueOpaqueOutbox(id, mailboxID string, payload []byte) error {
	if err := validateOpaqueToken(id); err != nil {
		return err
	}
	if err := validateOpaqueToken(mailboxID); err != nil {
		return err
	}
	_, err := d.DB.Exec(`
		INSERT INTO opaque_mailbox_outbox(id, mailbox_id, payload, stored_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET payload = excluded.payload, stored_at = excluded.stored_at
	`, id, mailboxID, payload, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("queue opaque mailbox envelope: %w", err)
	}
	return nil
}

func (d *Database) ListOpaqueOutbox(limit int) ([]OpaqueOutboxMessage, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.DB.Query(`
		SELECT id, mailbox_id, payload, stored_at
		FROM opaque_mailbox_outbox ORDER BY stored_at ASC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list opaque mailbox outbox: %w", err)
	}
	defer rows.Close()
	var messages []OpaqueOutboxMessage
	for rows.Next() {
		var stored OpaqueOutboxMessage
		if err := rows.Scan(&stored.ID, &stored.MailboxID, &stored.Payload, &stored.StoredAt); err != nil {
			return nil, fmt.Errorf("scan opaque mailbox outbox: %w", err)
		}
		messages = append(messages, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate opaque mailbox outbox: %w", err)
	}
	return messages, nil
}

func (d *Database) RemoveOpaqueOutbox(id string) error {
	_, err := d.DB.Exec(`DELETE FROM opaque_mailbox_outbox WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("remove opaque mailbox outbox entry: %w", err)
	}
	return nil
}

func (d *Database) StoreOpaqueHeldMessageForUser(id, mailboxID string, payload []byte, expiresAt int64, userKey []byte) (bool, error) {
	if err := validateOpaqueToken(id); err != nil {
		return false, fmt.Errorf("invalid opaque envelope ID: %w", err)
	}
	if err := validateOpaqueToken(mailboxID); err != nil {
		return false, fmt.Errorf("invalid mailbox ID: %w", err)
	}
	if len(payload) == 0 || len(payload) > MaxOpaqueEnvelopeSize || expiresAt <= time.Now().Unix() || time.Unix(expiresAt, 0).After(time.Now().Add(maxEnvelopeRetention)) {
		return false, fmt.Errorf("invalid held envelope")
	}
	if len(userKey) == 0 {
		return false, fmt.Errorf("missing authenticated user key")
	}

	userHash := hashSecurityKey("inkmail-hold-user-v1", userKey)
	envelopeHash := hashSecurityKey("inkmail-envelope-id-v1", []byte(id))
	mailboxHash := hashSecurityKey("inkmail-mailbox-id-v1", []byte(mailboxID))
	payloadHash := sha256.Sum256(payload)
	now := time.Now().Unix()
	tx, err := d.DB.Begin()
	if err != nil {
		return false, fmt.Errorf("begin held-envelope admission: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM opaque_envelope_dedup WHERE expires_at <= ?`, now); err != nil {
		return false, fmt.Errorf("expire replay records: %w", err)
	}
	if _, err := tx.Exec(`DELETE FROM opaque_held_messages WHERE expires_at <= ?`, now); err != nil {
		return false, fmt.Errorf("expire held envelopes: %w", err)
	}
	var oldMailboxHash, oldPayloadHash []byte
	err = tx.QueryRow(`SELECT mailbox_hash, payload_hash FROM opaque_envelope_dedup WHERE envelope_hash = ?`, envelopeHash[:]).Scan(&oldMailboxHash, &oldPayloadHash)
	if err == nil {
		if !sameDigest(oldMailboxHash, mailboxHash[:]) || !sameDigest(oldPayloadHash, payloadHash[:]) {
			return false, fmt.Errorf("envelope ID replay conflicts with previously accepted content")
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("check envelope replay: %w", err)
	}

	var heldCount int
	var heldBytes int64
	if err := tx.QueryRow(`SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM opaque_held_messages WHERE submitter_hash = ?`, userHash[:]).Scan(&heldCount, &heldBytes); err != nil {
		return false, fmt.Errorf("count user-held messages: %w", err)
	}
	if heldCount >= maxHeldMessagesPerUser || heldBytes+int64(len(payload)) > maxHeldBytesPerUser {
		return false, fmt.Errorf("authenticated user hold quota exceeded")
	}
	var seenCount int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM opaque_envelope_dedup WHERE submitter_hash = ? AND expires_at > ?`, userHash[:], now).Scan(&seenCount); err != nil {
		return false, fmt.Errorf("count user replay records: %w", err)
	}
	if seenCount >= maxSeenEnvelopesPerUser {
		return false, fmt.Errorf("authenticated user replay-record quota exceeded")
	}

	if _, err := tx.Exec(`INSERT INTO opaque_envelope_dedup(envelope_hash, mailbox_hash, payload_hash, submitter_hash, expires_at) VALUES (?, ?, ?, ?, ?)`, envelopeHash[:], mailboxHash[:], payloadHash[:], userHash[:], expiresAt); err != nil {
		return false, fmt.Errorf("record envelope replay guard: %w", err)
	}

	if _, err := tx.Exec(`INSERT INTO opaque_held_messages(id, mailbox_id, payload, expires_at, stored_at, submitter_hash) VALUES (?, ?, ?, ?, ?, ?)`, id, mailboxID, payload, expiresAt, now, userHash[:]); err != nil {
		return false, fmt.Errorf("store opaque held message: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit held-envelope admission: %w", err)
	}
	return true, nil
}

func (d *Database) ListOpaqueHeldMessages(mailboxID string, limit int) ([]OpaqueHeldMessage, error) {
	if err := validateOpaqueToken(mailboxID); err != nil {
		return nil, fmt.Errorf("invalid mailbox ID: %w", err)
	}
	if limit <= 0 || limit > 256 {
		limit = 256
	}
	rows, err := d.DB.Query(`
		SELECT id, mailbox_id, payload, expires_at, stored_at
		FROM opaque_held_messages
		WHERE mailbox_id = ? AND expires_at > ?
		ORDER BY stored_at ASC
		LIMIT ?
	`, mailboxID, time.Now().Unix(), limit)
	if err != nil {
		return nil, fmt.Errorf("list opaque held messages: %w", err)
	}
	defer rows.Close()
	var messages []OpaqueHeldMessage
	var payloadBytes int64
	for rows.Next() {
		var stored OpaqueHeldMessage
		if err := rows.Scan(&stored.ID, &stored.MailboxID, &stored.Payload,
			&stored.ExpiresAt, &stored.StoredAt); err != nil {
			return nil, fmt.Errorf("scan opaque held message: %w", err)
		}
		if len(messages) > 0 && payloadBytes+int64(len(stored.Payload)) > MaxOpaqueDeliveryBytes {
			break
		}
		payloadBytes += int64(len(stored.Payload))
		messages = append(messages, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate opaque held messages: %w", err)
	}
	return messages, nil
}

// DeleteOpaqueHeldMessage deletes a delivered envelope and erases freed SQLite
// pages before returning.
func (d *Database) DeleteOpaqueHeldMessage(id, mailboxID string) error {
	result, err := d.DB.Exec(`DELETE FROM opaque_held_messages WHERE id = ? AND mailbox_id = ?`, id, mailboxID)
	if err != nil {
		return fmt.Errorf("delete opaque held message: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check opaque message deletion: %w", err)
	}
	if deleted != 1 {
		return fmt.Errorf("held envelope is no longer available")
	}
	if _, err := d.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint delivered envelope deletion: %w", err)
	}
	return nil
}

func (d *Database) DeleteExpiredOpaqueHeldMessages() error {
	now := time.Now().Unix()
	_, err := d.DB.Exec(`DELETE FROM opaque_held_messages WHERE expires_at <= ?`, now)
	if err != nil {
		return fmt.Errorf("delete expired opaque held messages: %w", err)
	}
	if _, err := d.DB.Exec(`DELETE FROM opaque_envelope_dedup WHERE expires_at <= ?`, now); err != nil {
		return fmt.Errorf("delete expired envelope replay records: %w", err)
	}
	return nil
}

func (d *Database) backfillOpaqueEnvelopeDedup() error {
	var backfillDone string
	err := d.DB.QueryRow(`SELECT value FROM node_meta WHERE key = 'opaque_replay_backfill_v1'`).Scan(&backfillDone)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("check replay-record migration: %w", err)
	}
	now := time.Now().Unix()
	tx, err := d.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin replay-record migration: %w", err)
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id, mailbox_id, payload, expires_at FROM opaque_held_messages WHERE expires_at > ?`, now)
	if err != nil {
		return fmt.Errorf("read legacy held envelopes: %w", err)
	}
	for rows.Next() {
		var id, mailboxID string
		var payload []byte
		var expiresAt int64
		if err := rows.Scan(&id, &mailboxID, &payload, &expiresAt); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy held envelope: %w", err)
		}
		envelopeHash := hashSecurityKey("inkmail-envelope-id-v1", []byte(id))
		mailboxHash := hashSecurityKey("inkmail-mailbox-id-v1", []byte(mailboxID))
		payloadHash := sha256.Sum256(payload)
		if _, err := tx.Exec(`INSERT OR IGNORE INTO opaque_envelope_dedup(envelope_hash, mailbox_hash, payload_hash, submitter_hash, expires_at) VALUES (?, ?, ?, X'', ?)`, envelopeHash[:], mailboxHash[:], payloadHash[:], expiresAt); err != nil {
			rows.Close()
			return fmt.Errorf("backfill legacy replay record: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate legacy held envelopes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close legacy held envelopes: %w", err)
	}
	if _, err := tx.Exec(`INSERT INTO node_meta(key, value) VALUES ('opaque_replay_backfill_v1', 'done')`); err != nil {
		return fmt.Errorf("record replay-record migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit replay-record migration: %w", err)
	}
	return nil
}

func (d *Database) SetOwnedMailboxRoute(mailboxID, address string, expiresAt int64, ownerKey []byte) error {
	if err := validateOpaqueToken(mailboxID); err != nil {
		return fmt.Errorf("invalid mailbox ID: %w", err)
	}
	if strings.TrimSpace(address) == "" || expiresAt <= time.Now().Unix() || len(ownerKey) != 32 {
		return fmt.Errorf("invalid owned mailbox route")
	}
	ownerHash := hashSecurityKey("inkmail-mailbox-owner-v1", ownerKey)
	tx, err := d.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin mailbox route update: %w", err)
	}
	defer tx.Rollback()
	var storedHash []byte
	err = tx.QueryRow(`SELECT owner_key_hash FROM mailbox_owners WHERE mailbox_id = ?`, mailboxID).Scan(&storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.Exec(`INSERT INTO mailbox_owners(mailbox_id, owner_key_hash) VALUES (?, ?)`, mailboxID, ownerHash[:]); err != nil {
			return fmt.Errorf("claim mailbox ownership: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("read mailbox ownership: %w", err)
	} else if !sameDigest(storedHash, ownerHash[:]) {
		return fmt.Errorf("mailbox is owned by a different authenticated identity")
	}
	if _, err := tx.Exec(`
		INSERT INTO mailbox_routes(mailbox_id, address, expires_at, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(mailbox_id) DO UPDATE SET address = excluded.address,
			expires_at = excluded.expires_at, last_seen = excluded.last_seen
	`, mailboxID, address, expiresAt, time.Now().Unix()); err != nil {
		return fmt.Errorf("store owned mailbox route: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit mailbox route update: %w", err)
	}
	return nil
}

func (d *Database) MailboxOwnedBy(mailboxID string, ownerKey []byte) (bool, error) {
	if err := validateOpaqueToken(mailboxID); err != nil || len(ownerKey) != 32 {
		return false, fmt.Errorf("invalid mailbox ownership check")
	}
	ownerHash := hashSecurityKey("inkmail-mailbox-owner-v1", ownerKey)
	var storedHash []byte
	err := d.DB.QueryRow(`SELECT owner_key_hash FROM mailbox_owners WHERE mailbox_id = ?`, mailboxID).Scan(&storedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read mailbox ownership: %w", err)
	}
	return sameDigest(storedHash, ownerHash[:]), nil
}

func hashSecurityKey(label string, key []byte) [32]byte {
	hash := sha256.New()
	hash.Write([]byte(label))
	hash.Write([]byte{0})
	hash.Write(key)
	var digest [32]byte
	copy(digest[:], hash.Sum(nil))
	return digest
}

func sameDigest(first, second []byte) bool {
	if len(first) != len(second) {
		return false
	}
	for index := range first {
		if first[index] != second[index] {
			return false
		}
	}
	return true
}

func (d *Database) SetMailboxRoute(mailboxID, address string, expiresAt int64) error {
	if err := validateOpaqueToken(mailboxID); err != nil {
		return fmt.Errorf("invalid mailbox ID: %w", err)
	}
	if strings.TrimSpace(address) == "" || expiresAt <= time.Now().Unix() {
		return fmt.Errorf("invalid mailbox route")
	}
	_, err := d.DB.Exec(`
		INSERT INTO mailbox_routes(mailbox_id, address, expires_at, last_seen)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(mailbox_id) DO UPDATE SET
			address = excluded.address,
			expires_at = excluded.expires_at,
			last_seen = excluded.last_seen
	`, mailboxID, address, expiresAt, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store mailbox route: %w", err)
	}
	return nil
}

func (d *Database) GetMailboxRoute(mailboxID string) (string, error) {
	address, _, err := d.GetMailboxRouteWithExpiry(mailboxID)
	return address, err
}

func (d *Database) GetMailboxRouteWithExpiry(mailboxID string) (string, int64, error) {
	if err := validateOpaqueToken(mailboxID); err != nil {
		return "", 0, fmt.Errorf("invalid mailbox ID: %w", err)
	}
	var address string
	var expiresAt int64
	err := d.DB.QueryRow(`
		SELECT address, expires_at FROM mailbox_routes WHERE mailbox_id = ? AND expires_at > ?
	`, mailboxID, time.Now().Unix()).Scan(&address, &expiresAt)
	if err != nil {
		return "", 0, fmt.Errorf("get mailbox route: %w", err)
	}
	return address, expiresAt, nil
}

func (d *Database) DeleteExpiredMailboxRoutes() error {
	_, err := d.DB.Exec(`DELETE FROM mailbox_routes WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("delete expired mailbox routes: %w", err)
	}
	return nil
}

// MarkMessageDeliveredFromReceipt applies an authenticated recipient receipt
// only to the matching local outgoing message.
func (d *Database) MarkMessageDeliveredFromReceipt(
	messageID string,
	localNamespace string,
	localPublicKey []byte,
	recipientNamespace string,
	recipientPublicKey []byte,
) (bool, error) {
	tx, err := d.DB.Begin()
	if err != nil {
		return false, fmt.Errorf("begin delivery receipt update: %w", err)
	}
	defer tx.Rollback()

	var status string
	err = tx.QueryRow(`
		SELECT status FROM messages
		WHERE id = ? AND direction IN (?, ?) AND sender_namespace = ?
			AND sender_public_key = ? AND recipient_namespace = ?
			AND recipient_public_key = ?
	`, messageID, DirectionSent, DirectionQueued, localNamespace,
		localPublicKey, recipientNamespace, recipientPublicKey).Scan(&status)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("match delivery receipt: %w", err)
	}
	if status != StatusDelivered {
		if _, err := tx.Exec(`
			UPDATE messages SET status = ? WHERE id = ? AND direction IN (?, ?)
				AND sender_namespace = ? AND sender_public_key = ?
				AND recipient_namespace = ? AND recipient_public_key = ?
		`, StatusDelivered, messageID, DirectionSent, DirectionQueued,
			localNamespace, localPublicKey, recipientNamespace, recipientPublicKey); err != nil {
			return false, fmt.Errorf("mark message delivered from receipt: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit delivery receipt update: %w", err)
	}
	return true, nil
}

func validateOpaqueToken(value string) error {
	decoded, err := decodeHex(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("expected 32-byte hexadecimal token")
	}
	return nil
}
