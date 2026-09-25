package network

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

// mailboxOpBody is the wire body of MAILBOX_OP: one signed mutation.
type mailboxOpBody struct {
	MessageID string `json:"message_id"`
	Op        string `json:"op"`
	Folder    string `json:"folder,omitempty"`
	AuthorNS  string `json:"author_namespace"`
	AuthorKey string `json:"author_public_key"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// mailboxSyncRequest asks Daddy for ops newer than Since.
type mailboxSyncRequest struct {
	Namespace string `json:"namespace"`
	PublicKey string `json:"public_key"`
	Since     int64  `json:"since"`
	Limit     int    `json:"limit"`
}

// mailboxStateBody answers MAILBOX_SYNC with journalled ops and a watermark.
type mailboxStateBody struct {
	Ops       []mailboxOpBody `json:"ops"`
	NextSince int64           `json:"next_since"`
}

// toWireOp converts a stored op to its wire form.
func toWireOp(op database.MailboxOp) mailboxOpBody {
	return mailboxOpBody{
		MessageID: op.MessageID,
		Op:        op.Op,
		Folder:    op.Folder,
		AuthorNS:  op.AuthorNS,
		AuthorKey: hex.EncodeToString(op.AuthorKey),
		Timestamp: op.Timestamp,
		Signature: hex.EncodeToString(op.Signature),
	}
}

// toSignedRequest converts a wire op to the verifiable signed form.
func toSignedRequest(body mailboxOpBody) *message.MailboxOpRequest {
	return &message.MailboxOpRequest{
		MessageID: body.MessageID,
		Op:        body.Op,
		Folder:    body.Folder,
		AuthorNS:  body.AuthorNS,
		AuthorKey: body.AuthorKey,
		Timestamp: body.Timestamp,
		Signature: body.Signature,
	}
}

// mailboxMessageOwnership returns durable ownership metadata and supports
// databases upgraded while a message is still held.
func mailboxMessageOwnership(db *database.Database, messageID string) (*database.MailboxMessage, error) {
	owned, err := db.GetMailboxMessage(messageID)
	if err == nil {
		return owned, nil
	}

	held, heldErr := db.GetHeldMessage(messageID)
	if heldErr != nil {
		return nil, err
	}

	return &database.MailboxMessage{
		ID:                 messageID,
		SenderNamespace:    held.SenderNamespace,
		SenderPublicKey:    held.SenderPublicKey,
		RecipientNamespace: held.RecipientNamespace,
		RecipientPublicKey: held.RecipientPublicKey,
	}, nil
}

// verifyMailboxAuthor checks op signature, session binding and ownership.
// All three must pass; anything else is rejected without touching state.
func verifyMailboxAuthor(
	session *Session,
	db *database.Database,
	body mailboxOpBody,
) error {
	signed := toSignedRequest(body)

	if err := signed.Verify(); err != nil {
		return err
	}

	if err := verifySessionIdentity(
		session,
		body.AuthorNS,
		body.AuthorKey,
	); err != nil {
		return fmt.Errorf("mailbox op author mismatch: %w", err)
	}

	authorKey, err := decodeHexField(body.AuthorKey)
	if err != nil {
		return err
	}

	owned, err := mailboxMessageOwnership(db, body.MessageID)
	if err != nil {
		return fmt.Errorf("unknown message: %w", err)
	}

	senderKey := owned.SenderPublicKey

	recipientKey := owned.RecipientPublicKey

	owns := owned.SenderNamespace == body.AuthorNS &&
		sameBytes(senderKey, authorKey) ||
		owned.RecipientNamespace == body.AuthorNS &&
			sameBytes(recipientKey, authorKey)

	if !owns {
		return fmt.Errorf("author does not own message %s", body.MessageID)
	}

	return nil
}

// handleMailboxOp stores one verified op and applies it to held state.
func handleMailboxOp(
	session *Session,
	db *database.Database,
	raw json.RawMessage,
) error {
	var body mailboxOpBody

	if err := json.Unmarshal(raw, &body); err != nil {
		return replyMailboxOpAck(session, "", statusRejected, "invalid mailbox op")
	}

	if err := verifyMailboxAuthor(session, db, body); err != nil {
		return replyMailboxOpAck(session, body.MessageID, statusRejected, err.Error())
	}

	authorKey, err := decodeHexField(body.AuthorKey)
	if err != nil {
		return replyMailboxOpAck(session, body.MessageID, statusRejected, err.Error())
	}

	signature, err := decodeHexField(body.Signature)
	if err != nil {
		return replyMailboxOpAck(session, body.MessageID, statusRejected, err.Error())
	}

	op := database.MailboxOp{
		MessageID: strings.TrimSpace(body.MessageID),
		Op:        strings.ToLower(strings.TrimSpace(body.Op)),
		Folder:    strings.ToLower(strings.TrimSpace(body.Folder)),
		AuthorNS:  body.AuthorNS,
		AuthorKey: authorKey,
		Timestamp: body.Timestamp,
		Signature: signature,
	}

	if _, err := db.ApplyMailboxOp(op); err != nil {
		return replyMailboxOpAck(session, body.MessageID, statusRejected, err.Error())
	}

	return replyMailboxOpAck(session, body.MessageID, statusOK, "")
}

// handleMailboxSync replays ops newer than the watermark, filtered to
// messages the caller owns so users can never enumerate other mail.
func handleMailboxSync(
	session *Session,
	db *database.Database,
	raw json.RawMessage,
) error {
	var req mailboxSyncRequest

	if err := json.Unmarshal(raw, &req); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeMailboxState,
			Data: marshalJSON(mailboxStateBody{}),
		})
	}

	if err := verifySessionIdentity(session, req.Namespace, req.PublicKey); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeMailboxState,
			Data: marshalJSON(mailboxStateBody{}),
		})
	}

	callerKey, err := decodeHexField(req.PublicKey)
	if err != nil {
		return sendMessage(session, Message{
			Type: messageTypeMailboxState,
			Data: marshalJSON(mailboxStateBody{}),
		})
	}

	ops, next, err := db.ListMailboxOpsSince(req.Since, req.Limit)
	if err != nil {
		return sendMessage(session, Message{
			Type: messageTypeMailboxState,
			Data: marshalJSON(mailboxStateBody{NextSince: req.Since}),
		})
	}

	visible := make([]mailboxOpBody, 0, len(ops))

	for _, op := range ops {
		held, err := mailboxMessageOwnership(db, op.MessageID)
		if err != nil {
			continue
		}

		senderKey := held.SenderPublicKey

		recipientKey := held.RecipientPublicKey

		owns := held.SenderNamespace == req.Namespace &&
			sameBytes(senderKey, callerKey) ||
			held.RecipientNamespace == req.Namespace &&
				sameBytes(recipientKey, callerKey)

		if owns {
			visible = append(visible, toWireOp(op))
		}
	}

	return sendMessage(session, Message{
		Type: messageTypeMailboxState,
		Data: marshalJSON(mailboxStateBody{Ops: visible, NextSince: next}),
	})
}

// SendMailboxOp delivers one signed op to Daddy and requires MAILBOX_OP_ACK.
func SendMailboxOp(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
	op *message.MailboxOpRequest,
) error {
	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return err
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeMailboxOp,
		Data: marshalJSON(mailboxOpBody{
			MessageID: op.MessageID,
			Op:        op.Op,
			Folder:    op.Folder,
			AuthorNS:  op.AuthorNS,
			AuthorKey: op.AuthorKey,
			Timestamp: op.Timestamp,
			Signature: op.Signature,
		}),
	}); err != nil {
		return err
	}

	var reply Message

	if err := receiveMessage(session, &reply); err != nil {
		return err
	}

	if reply.Type != messageTypeMailboxOpAck {
		return fmt.Errorf("unexpected mailbox op response %q", reply.Type)
	}

	var ack ackBody

	if err := json.Unmarshal(reply.Data, &ack); err != nil {
		return err
	}

	if ack.Status != statusOK {
		if ack.Reason == "" {
			ack.Reason = "mailbox op rejected"
		}

		return fmt.Errorf("mailbox op rejected: %s", ack.Reason)
	}

	return nil
}

// mailboxSyncFromDaddy pulls ops from one Daddy, verifies signatures and
// applies LWW state. Forged ops are skipped, never applied.
func mailboxSyncFromDaddy(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
	since int64,
) (int64, error) {
	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return since, err
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeMailboxSync,
		Data: marshalJSON(mailboxSyncRequest{
			Namespace: local.Namespace,
			PublicKey: hex.EncodeToString(local.PublicKey),
			Since:     since,
			Limit:     200,
		}),
	}); err != nil {
		return since, err
	}

	var reply Message

	if err := receiveMessage(session, &reply); err != nil {
		return since, err
	}

	if reply.Type != messageTypeMailboxState {
		return since, fmt.Errorf("unexpected mailbox state %q", reply.Type)
	}

	var state mailboxStateBody

	if err := json.Unmarshal(reply.Data, &state); err != nil {
		return since, err
	}

	for _, wire := range state.Ops {
		if err := toSignedRequest(wire).Verify(); err != nil {
			continue
		}

		authorKey, err := decodeHexField(wire.AuthorKey)
		if err != nil {
			continue
		}

		signature, err := decodeHexField(wire.Signature)
		if err != nil {
			continue
		}

		_, _ = db.ApplyMailboxOp(database.MailboxOp{
			MessageID: wire.MessageID,
			Op:        strings.ToLower(strings.TrimSpace(wire.Op)),
			Folder:    strings.ToLower(strings.TrimSpace(wire.Folder)),
			AuthorNS:  wire.AuthorNS,
			AuthorKey: authorKey,
			Timestamp: wire.Timestamp,
			Signature: signature,
		})
	}

	if state.NextSince < since {
		return since, nil
	}

	return state.NextSince, nil
}

// BroadcastMailboxOp sends a signed op to every relay. One live Daddy is
// enough; local state was already applied offline-first.
func BroadcastMailboxOp(
	local *identity.Identity,
	db *database.Database,
	op *message.MailboxOpRequest,
) error {
	sent := 0

	var lastErr error

	for _, daddy := range DaddyAddresses(db, DefaultRelaysPath()) {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		if err := SendMailboxOp(daddy, local, db, op); err != nil {
			lastErr = err

			continue
		}

		sent++
	}

	if sent == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no relays configured")
		}

		return lastErr
	}

	return nil
}

// SyncMailboxOpsAll pulls from every relay and returns top watermark.
func SyncMailboxOpsAll(
	local *identity.Identity,
	db *database.Database,
	since int64,
) int64 {
	best := since

	for _, daddy := range DaddyAddresses(db, DefaultRelaysPath()) {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		if next, err := mailboxSyncFromDaddy(daddy, local, db, since); err == nil && next > best {
			best = next
		}
	}

	return best
}

// replyMailboxOpAck answers a MAILBOX_OP exchange.
func replyMailboxOpAck(
	session *Session,
	messageID string,
	status string,
	reason string,
) error {
	return sendMessage(session, Message{
		Type: messageTypeMailboxOpAck,
		Data: marshalJSON(ackBody{
			MessageID: messageID,
			Status:    status,
			Reason:    reason,
		}),
	})
}
