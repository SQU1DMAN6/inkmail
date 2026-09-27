package database

import (
	"fmt"
	"strings"
	"time"
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

// OpaqueOutboxMessage is a locally queued encrypted envelope.
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

// ListOpaqueOutbox returns queued opaque envelopes in FIFO order.
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

// RemoveOpaqueOutbox removes an envelope accepted by all configured relays.
func (d *Database) RemoveOpaqueOutbox(id string) error {
	_, err := d.DB.Exec(`DELETE FROM opaque_mailbox_outbox WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("remove opaque mailbox outbox entry: %w", err)
	}
	return nil
}

// StoreOpaqueHeldMessage stores an encrypted mailbox envelope without sender
// or recipient identity metadata.
func (d *Database) StoreOpaqueHeldMessage(id, mailboxID string, payload []byte, expiresAt int64) error {
	if err := validateOpaqueToken(id); err != nil {
		return fmt.Errorf("invalid opaque envelope ID: %w", err)
	}
	if err := validateOpaqueToken(mailboxID); err != nil {
		return fmt.Errorf("invalid mailbox ID: %w", err)
	}
	if len(payload) == 0 || expiresAt <= time.Now().Unix() {
		return fmt.Errorf("invalid held envelope")
	}
	_, err := d.DB.Exec(`
		INSERT INTO opaque_held_messages(id, mailbox_id, payload, expires_at, stored_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO NOTHING
	`, id, mailboxID, payload, expiresAt, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("store opaque held message: %w", err)
	}
	return nil
}

// ListOpaqueHeldMessages returns temporary ciphertext addressed to a mailbox.
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
	for rows.Next() {
		var stored OpaqueHeldMessage
		if err := rows.Scan(&stored.ID, &stored.MailboxID, &stored.Payload,
			&stored.ExpiresAt, &stored.StoredAt); err != nil {
			return nil, fmt.Errorf("scan opaque held message: %w", err)
		}
		messages = append(messages, stored)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate opaque held messages: %w", err)
	}
	return messages, nil
}

// OpaqueHeldMessageExists reports whether an envelope ID is already held.
func (d *Database) OpaqueHeldMessageExists(id string) (bool, error) {
	if err := validateOpaqueToken(id); err != nil {
		return false, err
	}
	var count int
	if err := d.DB.QueryRow(`SELECT COUNT(*) FROM opaque_held_messages WHERE id = ?`, id).Scan(&count); err != nil {
		return false, fmt.Errorf("check opaque held message: %w", err)
	}
	return count > 0, nil
}

// DeleteOpaqueHeldMessage deletes a delivered envelope and erases freed SQLite
// pages before returning.
func (d *Database) DeleteOpaqueHeldMessage(id, mailboxID string) error {
	result, err := d.DB.Exec(`DELETE FROM opaque_held_messages WHERE id = ? AND mailbox_id = ?`, id, mailboxID)
	if err != nil {
		return fmt.Errorf("delete opaque held message: %w", err)
	}
	_, err = result.RowsAffected()
	if err != nil {
		return fmt.Errorf("check opaque message deletion: %w", err)
	}
	if _, err := d.DB.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return fmt.Errorf("checkpoint delivered envelope deletion: %w", err)
	}
	return nil
}

// DeleteExpiredOpaqueHeldMessages removes expired temporary envelopes.
func (d *Database) DeleteExpiredOpaqueHeldMessages() error {
	_, err := d.DB.Exec(`DELETE FROM opaque_held_messages WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("delete expired opaque held messages: %w", err)
	}
	return nil
}

// SetMailboxRoute refreshes a temporary route keyed only by opaque mailbox ID.
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

// GetMailboxRoute returns an unexpired direct route for an opaque mailbox.
func (d *Database) GetMailboxRoute(mailboxID string) (string, error) {
	if err := validateOpaqueToken(mailboxID); err != nil {
		return "", fmt.Errorf("invalid mailbox ID: %w", err)
	}
	var address string
	err := d.DB.QueryRow(`
		SELECT address FROM mailbox_routes WHERE mailbox_id = ? AND expires_at > ?
	`, mailboxID, time.Now().Unix()).Scan(&address)
	if err != nil {
		return "", fmt.Errorf("get mailbox route: %w", err)
	}
	return address, nil
}

// DeleteExpiredMailboxRoutes removes stale opaque mailbox routes.
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
	result, err := d.DB.Exec(`
		UPDATE messages SET status = ?
		WHERE id = ? AND direction IN (?, ?) AND sender_namespace = ?
			AND sender_public_key = ? AND recipient_namespace = ?
			AND recipient_public_key = ? AND status != ?
	`, StatusDelivered, messageID, DirectionSent, DirectionQueued,
		localNamespace, localPublicKey, recipientNamespace,
		recipientPublicKey, StatusDelivered)
	if err != nil {
		return false, fmt.Errorf("mark message delivered from receipt: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("check receipt state update: %w", err)
	}
	return affected > 0, nil
}

func validateOpaqueToken(value string) error {
	decoded, err := decodeHex(value)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("expected 32-byte hexadecimal token")
	}
	return nil
}
