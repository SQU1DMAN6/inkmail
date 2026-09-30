package network

import (
	"fmt"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

func RetryQueuedMessages(local *identity.Identity, db *database.Database) (int, error) {
	queued, err := db.ListQueuedMessages(100)
	if err != nil {
		return 0, err
	}
	deliveredOrAccepted := 0
	var lastErr error
	for _, stored := range queued {
		outgoing := &stored.Message
		if outgoing.SenderNamespace != local.Namespace || outgoing.SenderPublicKey != fmt.Sprintf("%x", local.PublicKey) {
			lastErr = fmt.Errorf("queued message %s does not belong to this identity", outgoing.ID)
			continue
		}
		if err := outgoing.Verify(); err != nil {
			lastErr = fmt.Errorf("verify queued message %s: %w", outgoing.ID, err)
			continue
		}
		recipientKey, err := decodeHexField(outgoing.RecipientPublicKey)
		if err != nil {
			lastErr = err
			continue
		}
		contact, err := db.GetPeerIdentity(outgoing.RecipientNamespace, recipientKey)
		if err != nil {
			lastErr = fmt.Errorf("load contact for queued message %s: %w", outgoing.ID, err)
			continue
		}
		result, err := ResolveAndSend(local, db, outgoing.RecipientNamespace, recipientKey,
			contact.EncryptionPublicKey, contact.MailboxID, outgoing)
		if err != nil {
			lastErr = fmt.Errorf("retry queued message %s: %w", outgoing.ID, err)
			continue
		}
		status := database.StatusPending
		if result != nil && result.Delivered {
			status = database.StatusDelivered
		}
		if err := db.StoreMessage(outgoing, database.DirectionSent, status); err != nil {
			lastErr = fmt.Errorf("update queued message %s: %w", outgoing.ID, err)
			continue
		}
		deliveredOrAccepted++
	}
	return deliveredOrAccepted, lastErr
}
