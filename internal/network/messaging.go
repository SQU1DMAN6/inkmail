package network

// messaging.go implements the protocol dispatcher and the two delivery
// strategies used by ghost connections:
//
//   - direct delivery: an encrypted envelope is handed straight to the
//     recipient over a temporary connection
//   - hold-and-forward: the envelope is handed to Daddy for later delivery
//
// In both cases Daddy and any relay only ever see ciphertext because the
// subject and body are encrypted end-to-end before they leave the sender
// (SPEC sections 16, 17 and 43).

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

// HandleConnection completes the handshake on an inbound connection and
// serves exactly one protocol request before closing.
//
// The connection is temporary: it is never retained and never becomes a
// user-managed session.
func HandleConnection(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) error {
	session, err := acceptSession(conn, local, db)
	if err != nil {
		return err
	}

	defer session.Close()

	return serveSession(session, local, db)
}

// acceptSession performs the responder side of the handshake and records the
// now-authenticated peer.
func acceptSession(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) (*Session, error) {
	if err := conn.SetDeadline(
		time.Now().Add(effectiveSessionTimeout()),
	); err != nil {
		_ = conn.Close()

		return nil, err
	}

	session, err := negotiateAsResponder(conn, local)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	// The peer address is what the peer's ghost connection came from. It is
	// a usable direct route for the lifetime of the route TTL.
	address := ""

	if conn.RemoteAddr() != nil {
		address = conn.RemoteAddr().String()
	}

	recordInboundPeer(db, session, address)

	return session, nil
}

// serveSession reads requests until the peer closes the connection and
// dispatches each of them to the correct handler.
//
// A ghost connection is normally single-exchange, but hold-and-forward needs
// two: FETCH_MESSAGES is answered with MESSAGE_DELIVERY and each delivered
// envelope is then acknowledged with DELIVERY_ACK. The loop is bounded so a
// peer cannot keep a temporary connection alive indefinitely.
func serveSession(
	session *Session,
	local *identity.Identity,
	db *database.Database,
) error {
	for exchanges := 0; exchanges < maxSessionRequests; exchanges++ {
		var request Message

		if err := receiveMessage(session, &request); err != nil {
			// The peer closing the connection after its final
			// acknowledgement is the normal end of a ghost connection.
			if errors.Is(err, io.EOF) ||
				errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf(
				"read request: %w",
				err,
			)
		}

		if session.Conn != nil {
			if err := session.Conn.SetDeadline(
				time.Now().Add(effectiveSessionTimeout()),
			); err != nil {
				return err
			}
		}

		if err := dispatchRequest(
			session,
			local,
			db,
			request,
		); err != nil {
			return err
		}
	}

	return fmt.Errorf(
		"session exceeded %d protocol exchanges",
		maxSessionRequests,
	)
}

// dispatchRequest routes one validated protocol request to its handler.
func dispatchRequest(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	request Message,
) error {
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

	case messageTypeDeleteMessage:
		return handleDeleteMessage(session, db, request.Data)

	default:
		return fmt.Errorf(
			"unsupported protocol message %q",
			request.Type,
		)
	}
}

// handleIncomingMessage receives a direct end-to-end encrypted envelope,
// verifies it, stores it and acknowledges delivery.
func handleIncomingMessage(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	data []byte,
) error {
	var envelope message.EncryptedMessage

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

	switch {
	case envelope.RecipientPublicKey !=
		hex.EncodeToString(local.PublicKey):

		status = statusRejected
		reason = "recipient mismatch"

	default:
		if err := receiveEncryptedEnvelope(
			db,
			local,
			envelope,
		); err != nil {
			status = statusRejected
			reason = err.Error()
		}
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

// receiveEncryptedEnvelope verifies and stores an end-to-end encrypted
// message. Verification happens before decryption (SPEC section 19).
func receiveEncryptedEnvelope(
	db *database.Database,
	local *identity.Identity,
	envelope message.EncryptedMessage,
) error {
	if err := envelope.Verify(); err != nil {
		return fmt.Errorf(
			"signature verification failed: %w",
			err,
		)
	}

	decrypted, err := envelope.DecryptFromSender(
		local.EncryptionPrivateKey,
		local.Namespace,
	)
	if err != nil {
		return fmt.Errorf(
			"decrypt message: %w",
			err,
		)
	}

	if decrypted.ID != envelope.ID {
		return fmt.Errorf(
			"message ID mismatch",
		)
	}

	// The ID is derived from stable message content, so only the legitimate
	// recipient can recompute it (SPEC section 20).
	if err := decrypted.VerifyID(); err != nil {
		return fmt.Errorf(
			"message ID verification failed: %w",
			err,
		)
	}

	senderKey, err := decodeHexField(envelope.SenderPublicKey)
	if err != nil {
		return err
	}

	// Rebuild the plaintext message and persist it locally. The stored
	// representation is the decrypted form because this node is the
	// legitimate recipient.
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

// ackBody is the shared body of every acknowledgement message.
type ackBody struct {
	MessageID string `json:"message_id,omitempty"`
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

// deliverEnvelopeLocally verifies, decrypts and stores one envelope that was
// delivered by Daddy, and reports the status Daddy needs (SPEC section 24).
//
// A rejected envelope is deliberately not deleted on Daddy's side: it is
// retried until its expiry is reached (SPEC section 25).
func deliverEnvelopeLocally(
	db *database.Database,
	local *identity.Identity,
	envelope message.EncryptedMessage,
) (string, string) {
	if err := receiveEncryptedEnvelope(
		db,
		local,
		envelope,
	); err != nil {
		return statusRejected, err.Error()
	}

	return statusDelivered, ""
}
