package network

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

func HandleConnection(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) error {
	source := "source:" + sourceAddressKey(conn.RemoteAddr())
	if !handshakeFailureLimiter.allow(source, time.Now()) {
		runtimeStats.rejectedHandshakes.Add(1)
		_ = conn.Close()
		return errors.New("handshake source temporarily throttled")
	}
	select {
	case handshakeSlots <- struct{}{}:
	default:
		runtimeStats.rejectedHandshakes.Add(1)
		_ = conn.Close()
		return errors.New("handshake capacity exceeded")
	}
	session, attemptIdentity, err := acceptSession(conn, local, db)
	<-handshakeSlots
	if err != nil {
		handshakeFailureLimiter.failed(source, time.Now())
		if attemptIdentity != "" {
			handshakeFailureLimiter.failed(attemptIdentity, time.Now())
		}
		runtimeStats.failedHandshakes.Add(1)
		return err
	}
	handshakeFailureLimiter.succeeded(source)
	if attemptIdentity != "" {
		handshakeFailureLimiter.succeeded(attemptIdentity)
	}

	defer session.Close()
	runtimeStats.authenticatedSession.Add(1)
	defer runtimeStats.authenticatedSession.Add(-1)

	return serveSession(session, local, db)
}

func acceptSession(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) (*Session, string, error) {
	if err := conn.SetDeadline(
		time.Now().Add(effectiveSessionTimeout()),
	); err != nil {
		_ = conn.Close()

		return nil, "", err
	}

	session, attemptIdentity, err := negotiateAsResponder(conn, local)
	if err != nil {
		_ = conn.Close()

		return nil, attemptIdentity, err
	}

	address := ""

	if conn.RemoteAddr() != nil {
		address = conn.RemoteAddr().String()
	}

	recordInboundPeer(db, session, address)

	return session, attemptIdentity, nil
}

func serveSession(
	session *Session,
	local *identity.Identity,
	db *database.Database,
) error {
	for exchanges := 0; exchanges < maxSessionRequests; exchanges++ {
		identityKey := session.PeerFingerprint()
		if !inFlightRequests.acquire(identityKey) {
			runtimeStats.rejectedRequests.Add(1)
			return errors.New("concurrent request capacity exceeded")
		}
		err := func() error {
			defer inFlightRequests.release(identityKey)
			var request Message
			if err := receiveMessage(session, &request); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
					return io.EOF
				}
				return fmt.Errorf("read request: %w", err)
			}
			if session.Conn != nil {
				if err := session.Conn.SetDeadline(time.Now().Add(effectiveSessionTimeout())); err != nil {
					return err
				}
			}
			return dispatchRequest(session, local, db, request)
		}()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}

	return fmt.Errorf(
		"session exceeded %d protocol exchanges",
		maxSessionRequests,
	)
}

func dispatchRequest(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	request Message,
) (err error) {
	defer func() {
		if err != nil {
			runtimeStats.rejectedRequests.Add(1)
		}
	}()
	now := time.Now()
	var remoteAddress net.Addr
	if session.Conn != nil {
		remoteAddress = session.Conn.RemoteAddr()
	}
	if !requestRateLimiter.allow("identity:"+session.PeerFingerprint(), now) ||
		!requestRateLimiter.allow("source:"+sourceAddressKey(remoteAddress), now) {
		runtimeStats.rateLimitEvents.Add(1)
		return fmt.Errorf("authenticated request rate limit exceeded")
	}
	if mailboxID := requestMailboxID(request); mailboxID != "" &&
		!requestRateLimiter.allow("mailbox:"+mailboxID, now) {
		runtimeStats.rateLimitEvents.Add(1)
		return fmt.Errorf("mailbox request rate limit exceeded")
	}

	switch request.Type {
	case messageTypeMessage:
		return handleIncomingMessage(session, local, db, request.Data)

	case messageTypeHoldMessage:
		return handleHoldMessage(session, local, db, request.Data)

	case messageTypeFetchMessages:
		return handleFetchMessages(session, db, request.Data)

	case messageTypeDeliveryAck:
		return handleDeliveryAck(session, db, request.Data)

	case messageTypeRegisterRoute:
		return handleRegisterRoute(session, db, request.Data)

	case messageTypeLookupRoute:
		return handleLookupRoute(session, db, request.Data)

	case messageTypeRelayProbe:
		return handleRelayProbe(session, request.Data)

	case messageTypeGhostForward:
		return handleGhostForward(session, local, db, request.Data)

	default:
		return fmt.Errorf(
			"unsupported protocol message %q",
			request.Type,
		)
	}
}

func requestMailboxID(request Message) string {
	switch request.Type {
	case messageTypeRegisterRoute, messageTypeLookupRoute, messageTypeHoldMessage,
		messageTypeFetchMessages, messageTypeDeliveryAck:
		var body struct {
			MailboxID string `json:"mailbox_id"`
		}
		if err := json.Unmarshal(request.Data, &body); err != nil || message.ValidateMailboxID(body.MailboxID) != nil {
			return ""
		}
		return strings.ToLower(body.MailboxID)
	default:
		return ""
	}
}

func handleIncomingMessage(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	data []byte,
) error {
	var envelope message.MailboxEnvelope

	if err := json.Unmarshal(data, &envelope); err != nil {
		_ = sendMessage(session, Message{
			Type: messageTypeMessageAck,
			Data: marshalJSON(ackBody{
				MessageID: "",
				Status:    statusRejected,
				Reason:    "malformed envelope",
			}),
		})

		return fmt.Errorf(
			"unmarshal encrypted message: %w",
			err,
		)
	}

	status := statusDelivered
	reason := ""
	if err := envelope.Validate(); err != nil {
		status = statusRejected
		reason = err.Error()
	} else if err := receiveMailboxEnvelope(db, local, envelope); err != nil {
		status = statusRejected
		reason = err.Error()
	}

	return sendMessage(session, Message{
		Type: messageTypeMessageAck,
		Data: marshalJSON(ackBody{
			MessageID: envelope.ID,
			Status:    status,
			Reason:    reason,
		}),
	})
}

func decryptEncryptedEnvelope(
	local *identity.Identity,
	envelope message.EncryptedMessage,
) (*message.Message, error) {
	if err := envelope.Verify(); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}
	decrypted, err := envelope.DecryptFromSender(local.EncryptionPrivateKey, local.Namespace)
	if err != nil {
		return nil, fmt.Errorf("decrypt message: %w", err)
	}
	if decrypted.ID != envelope.ID {
		return nil, fmt.Errorf("message ID mismatch")
	}
	if err := decrypted.VerifyID(); err != nil {
		return nil, fmt.Errorf("message ID verification failed: %w", err)
	}
	if decrypted.RecipientNamespace != local.Namespace ||
		!strings.EqualFold(decrypted.RecipientPublicKey, hex.EncodeToString(local.PublicKey)) {
		return nil, fmt.Errorf("recipient identity mismatch")
	}
	return decrypted, nil
}

func receiveEncryptedEnvelope(
	db *database.Database,
	local *identity.Identity,
	envelope message.EncryptedMessage,
) error {
	decrypted, err := decryptEncryptedEnvelope(local, envelope)
	if err != nil {
		return err
	}

	senderKey, err := decodeHexField(envelope.SenderPublicKey)
	if err != nil {
		return err
	}

	stored := &message.Message{
		ID:                 decrypted.ID,
		SenderNamespace:    envelope.SenderNamespace,
		SenderPublicKey:    envelope.SenderPublicKey,
		RecipientNamespace: envelope.RecipientNamespace,
		RecipientPublicKey: envelope.RecipientPublicKey,
		Subject:            decrypted.Subject,
		Body:               decrypted.Body,
		CreatedAt:          envelope.CreatedAt,
		Signature:          envelope.Signature,
	}

	if err := db.StoreMessage(stored, database.DirectionReceived, statusDelivered); err != nil {
		return err
	}

	if err := db.RecordPeerIdentity(
		envelope.SenderNamespace,
		senderKey,
	); err != nil {
		return err
	}

	return nil
}

const deliveryReceiptSubject = "InkMail internal delivery receipt v3"

type deliveryReceiptContent struct {
	MessageID string `json:"message_id"`
}

func receiveMailboxEnvelope(
	db *database.Database,
	local *identity.Identity,
	envelope message.MailboxEnvelope,
) error {
	mailboxID, err := db.GetOrCreateMailboxID()
	if err != nil {
		return err
	}
	payload, err := envelope.Open(local.EncryptionPrivateKey, mailboxID)
	if err != nil {
		return err
	}
	decrypted, err := decryptEncryptedEnvelope(local, payload.Envelope)
	if err != nil {
		return err
	}
	if payload.Kind == "delivery_receipt" {
		var receipt deliveryReceiptContent
		if err := json.Unmarshal([]byte(decrypted.Body), &receipt); err != nil || strings.TrimSpace(receipt.MessageID) == "" {
			return fmt.Errorf("invalid delivery receipt")
		}
		recipientKey, err := decodeHexField(decrypted.SenderPublicKey)
		if err != nil {
			return err
		}
		matched, err := db.MarkMessageDeliveredFromReceipt(
			receipt.MessageID,
			local.Namespace,
			local.PublicKey,
			decrypted.SenderNamespace,
			recipientKey,
		)
		if err != nil {
			return err
		}
		if !matched {
			return fmt.Errorf("delivery receipt does not match a local outgoing message")
		}
		return nil
	}

	if err := receiveEncryptedEnvelope(db, local, payload.Envelope); err != nil {
		return err
	}
	senderKey, err := decodeHexField(decrypted.SenderPublicKey)
	if err != nil {
		return err
	}
	senderEncryptionKey, err := decodeHexField(payload.SenderEncryptionKey)
	if err != nil {
		return err
	}
	if err := db.RecordPeerContact(decrypted.SenderNamespace, senderKey,
		senderEncryptionKey, payload.SenderMailboxID); err != nil {
		return err
	}
	return sendDeliveryReceiptToRelays(db, local, decrypted, payload, senderKey, senderEncryptionKey)
}

func sendDeliveryReceiptToRelays(
	db *database.Database,
	local *identity.Identity,
	original *message.Message,
	payload *message.MailboxPayload,
	senderKey []byte,
	senderEncryptionKey []byte,
) error {
	receiptBody, err := json.Marshal(deliveryReceiptContent{MessageID: original.ID})
	if err != nil {
		return err
	}
	receiptMessage, err := message.New(local, original.SenderNamespace,
		ed25519.PublicKey(senderKey), deliveryReceiptSubject, string(receiptBody))
	if err != nil {
		return err
	}
	inner, err := receiptMessage.EncryptForRecipient(senderEncryptionKey,
		original.SenderNamespace, local.PrivateKey)
	if err != nil {
		return err
	}
	localMailboxID, err := db.GetOrCreateMailboxID()
	if err != nil {
		return err
	}
	outer, err := message.WrapDeliveryReceipt(*inner, payload.SenderMailboxID,
		localMailboxID, local.EncryptionPublicKey, senderEncryptionKey)
	if err != nil {
		return err
	}
	return queueAndSendOpaqueEnvelope(db, local, outer)
}

// ackBody is the shared body of every acknowledgement message.
type ackBody struct {
	MessageID string `json:"message_id,omitempty"`
	MailboxID string `json:"mailbox_id,omitempty"`
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
}

// marshalJSON is a convenience wrapper used for protocol bodies.
func marshalJSON(value interface{}) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		return []byte("{}")
	}

	return data
}

// decodeHexField decodes a hex field, returning a helpful error.
func decodeHexField(value string) ([]byte, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf(
			"decode hex field: %w",
			err,
		)
	}

	return decoded, nil
}

// sendAck sends a single acknowledgement message.
func sendAck(
	session *Session,
	messageType string,
	messageID string,
	status string,
	reason string,
) error {
	return sendMessage(session, Message{
		Type: messageType,
		Data: marshalJSON(ackBody{
			MessageID: messageID,
			Status:    status,
			Reason:    reason,
		}),
	})
}
