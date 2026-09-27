package network

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

func queueAndSendOpaqueEnvelope(
	db *database.Database,
	local *identity.Identity,
	envelope *message.MailboxEnvelope,
) error {
	if err := envelope.Validate(); err != nil {
		return err
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("marshal opaque mailbox envelope: %w", err)
	}
	if err := db.QueueOpaqueOutbox(envelope.ID, envelope.MailboxID, payload); err != nil {
		return err
	}
	_ = SyncOpaqueMailboxOutbox(local, db)
	return nil
}

// SyncOpaqueMailboxOutbox submits each pending ciphertext to every configured
// Daddy and removes the local outbox entry only after all accept it.
func SyncOpaqueMailboxOutbox(local *identity.Identity, db *database.Database) error {
	queued, err := db.ListOpaqueOutbox(200)
	if err != nil {
		return err
	}
	var lastErr error
	for _, stored := range queued {
		var envelope message.MailboxEnvelope
		if err := json.Unmarshal(stored.Payload, &envelope); err != nil || envelope.Validate() != nil {
			lastErr = fmt.Errorf("invalid opaque mailbox outbox entry")
			continue
		}
		allAccepted := true
		for _, daddy := range DaddyAddresses(db, DefaultRelaysPath()) {
			if strings.TrimSpace(daddy) == "" {
				continue
			}
			if err := SendHoldMessage(daddy, local, db, &envelope); err != nil {
				allAccepted = false
				lastErr = err
			}
		}
		if allAccepted {
			if err := db.RemoveOpaqueOutbox(envelope.ID); err != nil {
				lastErr = err
			}
		}
	}
	return lastErr
}

// FetchMailboxAll polls each configured Daddy for the local opaque mailbox.
func FetchMailboxAll(local *identity.Identity, db *database.Database) (int, error) {
	return fetchViaRelays(DaddyAddresses(db, DefaultRelaysPath()), local, db)
}
