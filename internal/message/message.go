package message

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

const (
	maxSubjectLength = 256
	maxBodyLength    = 1024 * 1024
)

type Message struct {
	ID                 string `json:"id"`
	SenderNamespace    string `json:"sender_namespace"`
	SenderPublicKey    string `json:"sender_public_key"`
	RecipientNamespace string `json:"recipient_namespace"`
	RecipientPublicKey string `json:"recipient_public_key"`
	Subject            string `json:"subject"`
	Body               string `json:"body"`
	CreatedAt          int64  `json:"created_at"`
	Signature          string `json:"signature"`
}

func New(
	sender *identity.Identity,
	recipientNamespace string,
	recipientPublicKey ed25519.PublicKey,
	subject string,
	body string,
) (*Message, error) {
	if err := identity.ValidateNamespace(recipientNamespace); err != nil {
		return nil, fmt.Errorf(
			"invalid recipient namespace: %w",
			err,
		)
	}

	if len(recipientPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid recipient public key",
		)
	}

	subject = strings.TrimSpace(subject)

	if subject == "" {
		return nil, fmt.Errorf(
			"subject cannot be empty",
		)
	}

	if len(subject) > maxSubjectLength {
		return nil, fmt.Errorf(
			"subject cannot exceed %d bytes",
			maxSubjectLength,
		)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf(
			"message body cannot be empty",
		)
	}

	if len(body) > maxBodyLength {
		return nil, fmt.Errorf(
			"message body cannot exceed %d bytes",
			maxBodyLength,
		)
	}

	msg := &Message{
		SenderNamespace: sender.Namespace,
		SenderPublicKey: hex.EncodeToString(
			sender.PublicKey,
		),
		RecipientNamespace: recipientNamespace,
		RecipientPublicKey: hex.EncodeToString(
			recipientPublicKey,
		),
		Subject:   subject,
		Body:      body,
		CreatedAt: time.Now().Unix(),
	}

	msg.ID = msg.calculateID()

	signature := ed25519.Sign(
		sender.PrivateKey,
		msg.signingBytes(),
	)

	msg.Signature = hex.EncodeToString(signature)

	return msg, nil
}

func (m *Message) calculateID() string {
	sum := sha256.Sum256(
		m.signingBytes(),
	)

	return hex.EncodeToString(sum[:])
}

func (m *Message) signingBytes() []byte {
	type unsignedMessage struct {
		SenderNamespace    string `json:"sender_namespace"`
		SenderPublicKey    string `json:"sender_public_key"`
		RecipientNamespace string `json:"recipient_namespace"`
		RecipientPublicKey string `json:"recipient_public_key"`
		Subject            string `json:"subject"`
		Body               string `json:"body"`
		CreatedAt          int64  `json:"created_at"`
	}

	data, _ := json.Marshal(
		unsignedMessage{
			SenderNamespace:    m.SenderNamespace,
			SenderPublicKey:    m.SenderPublicKey,
			RecipientNamespace: m.RecipientNamespace,
			RecipientPublicKey: m.RecipientPublicKey,
			Subject:            m.Subject,
			Body:               m.Body,
			CreatedAt:          m.CreatedAt,
		},
	)

	return data
}

func (m *Message) Verify() error {
	if m.ID == "" {
		return fmt.Errorf(
			"message has no ID",
		)
	}

	if err := identity.ValidateNamespace(
		m.SenderNamespace,
	); err != nil {
		return fmt.Errorf(
			"invalid sender namespace: %w",
			err,
		)
	}

	if err := identity.ValidateNamespace(
		m.RecipientNamespace,
	); err != nil {
		return fmt.Errorf(
			"invalid recipient namespace: %w",
			err,
		)
	}

	senderPublic, err := hex.DecodeString(
		m.SenderPublicKey,
	)
	if err != nil ||
		len(senderPublic) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid sender public key",
		)
	}

	recipientPublic, err := hex.DecodeString(
		m.RecipientPublicKey,
	)
	if err != nil ||
		len(recipientPublic) != ed25519.PublicKeySize {
		return fmt.Errorf(
			"invalid recipient public key",
		)
	}

	expectedID := m.calculateID()

	if !strings.EqualFold(
		m.ID,
		expectedID,
	) {
		return fmt.Errorf(
			"message ID does not match message contents",
		)
	}

	signature, err := hex.DecodeString(
		m.Signature,
	)
	if err != nil ||
		len(signature) != ed25519.SignatureSize {
		return fmt.Errorf(
			"invalid message signature",
		)
	}

	if !ed25519.Verify(
		ed25519.PublicKey(senderPublic),
		m.signingBytes(),
		signature,
	) {
		return fmt.Errorf(
			"invalid message signature",
		)
	}

	return nil
}

func (m *Message) SenderKey() (ed25519.PublicKey, error) {
	key, err := hex.DecodeString(
		m.SenderPublicKey,
	)
	if err != nil ||
		len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid sender public key",
		)
	}

	return ed25519.PublicKey(key), nil
}

func (m *Message) RecipientKey() (ed25519.PublicKey, error) {
	key, err := hex.DecodeString(
		m.RecipientPublicKey,
	)
	if err != nil ||
		len(key) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid recipient public key",
		)
	}

	return ed25519.PublicKey(key), nil
}
