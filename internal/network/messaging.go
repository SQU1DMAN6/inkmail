package network

import (
	"encoding/json"
	"fmt"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

const (
	messageTypeSend = "MESSAGE"
	messageTypeAck  = "MESSAGE_ACK"

	messageStatusReceived = "received"
	messageStatusSent     = "sent"
	messageStatusFailed   = "failed"
)

type MessageEnvelope struct {
	Message message.Message `json:"message"`
}

type MessageAck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

func SendMessage(
	session *Session,
	db *database.Database,
	msg *message.Message,
) error {
	if session == nil {
		return fmt.Errorf(
			"session cannot be nil",
		)
	}

	if msg == nil {
		return fmt.Errorf(
			"message cannot be nil",
		)
	}

	if err := msg.Verify(); err != nil {
		return fmt.Errorf(
			"verify message: %w",
			err,
		)
	}

	recipientKey, err := msg.RecipientKey()
	if err != nil {
		return err
	}

	if msg.RecipientNamespace != session.PeerNamespace ||
		!recipientKey.Equal(session.Peer) {
		return fmt.Errorf(
			"message recipient does not match connected peer",
		)
	}

	if err := db.StoreMessage(
		msg,
		"sent",
		"pending",
	); err != nil {
		return err
	}

	data, err := json.Marshal(
		MessageEnvelope{
			Message: *msg,
		},
	)
	if err != nil {
		return fmt.Errorf(
			"encode message: %w",
			err,
		)
	}

	if err := sendMessage(
		session.Conn,
		Message{
			Type: messageTypeSend,
			Data: data,
		},
	); err != nil {
		_ = db.UpdateMessageStatus(
			msg.ID,
			messageStatusFailed,
		)

		return fmt.Errorf(
			"send message: %w",
			err,
		)
	}

	var incoming Message

	if err := receiveMessage(
		session.Conn,
		&incoming,
	); err != nil {
		_ = db.UpdateMessageStatus(
			msg.ID,
			messageStatusFailed,
		)

		return fmt.Errorf(
			"receive message acknowledgement: %w",
			err,
		)
	}

	if incoming.Type != messageTypeAck {
		_ = db.UpdateMessageStatus(
			msg.ID,
			messageStatusFailed,
		)

		return fmt.Errorf(
			"expected MESSAGE_ACK, got %q",
			incoming.Type,
		)
	}

	var ack MessageAck

	if err := json.Unmarshal(
		incoming.Data,
		&ack,
	); err != nil {
		_ = db.UpdateMessageStatus(
			msg.ID,
			messageStatusFailed,
		)

		return fmt.Errorf(
			"decode message acknowledgement: %w",
			err,
		)
	}

	if ack.ID != msg.ID {
		_ = db.UpdateMessageStatus(
			msg.ID,
			messageStatusFailed,
		)

		return fmt.Errorf(
			"message acknowledgement ID mismatch",
		)
	}

	if ack.Status != "stored" {
		_ = db.UpdateMessageStatus(
			msg.ID,
			messageStatusFailed,
		)

		if ack.Error != "" {
			return fmt.Errorf(
				"peer rejected message: %s",
				ack.Error,
			)
		}

		return fmt.Errorf(
			"peer rejected message",
		)
	}

	if err := db.UpdateMessageStatus(
		msg.ID,
		messageStatusSent,
	); err != nil {
		return err
	}

	return nil
}

func handleIncomingMessage(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	data []byte,
) error {
	var envelope MessageEnvelope

	if err := json.Unmarshal(
		data,
		&envelope,
	); err != nil {
		return sendMessageAck(
			session,
			MessageAck{
				Status: "rejected",
				Error:  "invalid message payload",
			},
		)
	}

	msg := &envelope.Message

	if err := msg.Verify(); err != nil {
		return sendMessageAck(
			session,
			MessageAck{
				ID:     msg.ID,
				Status: "rejected",
				Error:  err.Error(),
			},
		)
	}

	senderKey, err := msg.SenderKey()
	if err != nil {
		return sendMessageAck(
			session,
			MessageAck{
				ID:     msg.ID,
				Status: "rejected",
				Error:  err.Error(),
			},
		)
	}

	if msg.SenderNamespace != session.PeerNamespace ||
		!senderKey.Equal(session.Peer) {
		return sendMessageAck(
			session,
			MessageAck{
				ID:     msg.ID,
				Status: "rejected",
				Error:  "message sender does not match connected peer",
			},
		)
	}

	recipientKey, err := msg.RecipientKey()
	if err != nil {
		return sendMessageAck(
			session,
			MessageAck{
				ID:     msg.ID,
				Status: "rejected",
				Error:  err.Error(),
			},
		)
	}

	if msg.RecipientNamespace != local.Namespace ||
		!recipientKey.Equal(local.PublicKey) {
		return sendMessageAck(
			session,
			MessageAck{
				ID:     msg.ID,
				Status: "rejected",
				Error:  "message recipient is not this node",
			},
		)
	}

	if err := db.StoreMessage(
		msg,
		"received",
		messageStatusReceived,
	); err != nil {
		return sendMessageAck(
			session,
			MessageAck{
				ID:     msg.ID,
				Status: "rejected",
				Error:  err.Error(),
			},
		)
	}

	return sendMessageAck(
		session,
		MessageAck{
			ID:     msg.ID,
			Status: "stored",
		},
	)
}

func sendMessageAck(
	session *Session,
	ack MessageAck,
) error {
	data, err := json.Marshal(ack)
	if err != nil {
		return err
	}

	return sendMessage(
		session.Conn,
		Message{
			Type: messageTypeAck,
			Data: data,
		},
	)
}
