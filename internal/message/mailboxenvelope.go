package message

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	mailboxIDSize      = 32
	mailboxPaddingSize = 64 * 1024
	mailboxLabel       = "inkmail-opaque-mailbox-v1"
	maxMailboxPayload  = 4 * 1024 * 1024
)

type MailboxEnvelope struct {
	ID                 string `json:"id"`
	MailboxID          string `json:"mailbox_id"`
	EphemeralPublicKey string `json:"ephemeral_public_key"`
	Nonce              []byte `json:"nonce"`
	Ciphertext         []byte `json:"ciphertext"`
}

type MailboxPayload struct {
	Kind                string           `json:"kind"`
	Envelope            EncryptedMessage `json:"envelope"`
	SenderMailboxID     string           `json:"sender_mailbox_id"`
	SenderEncryptionKey string           `json:"sender_encryption_key"`
}

func (envelope *MailboxEnvelope) Validate() error {
	if envelope == nil {
		return fmt.Errorf("missing mailbox envelope")
	}
	if err := ValidateMailboxID(envelope.ID); err != nil {
		return fmt.Errorf("invalid opaque envelope ID: %w", err)
	}
	if err := ValidateMailboxID(envelope.MailboxID); err != nil {
		return fmt.Errorf("invalid mailbox ID: %w", err)
	}
	ephemeral, err := hex.DecodeString(envelope.EphemeralPublicKey)
	if err != nil || len(ephemeral) != 32 {
		return fmt.Errorf("invalid mailbox ephemeral key")
	}
	if len(envelope.Nonce) != chacha20poly1305.NonceSize || len(envelope.Ciphertext) < chacha20poly1305.Overhead {
		return fmt.Errorf("invalid opaque mailbox ciphertext")
	}
	return nil
}

func ValidateMailboxID(value string) error {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != mailboxIDSize {
		return fmt.Errorf("invalid mailbox identifier")
	}
	return nil
}

func NewMailboxID() (string, error) {
	value := make([]byte, mailboxIDSize)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", fmt.Errorf("generate mailbox identifier: %w", err)
	}
	return hex.EncodeToString(value), nil
}

func WrapForMailbox(
	inner EncryptedMessage,
	mailboxID string,
	senderMailboxID string,
	senderEncryptionKey []byte,
	recipientEncryptionKey []byte,
) (*MailboxEnvelope, error) {
	return wrapForMailbox(MailboxPayload{
		Kind:                "message",
		Envelope:            inner,
		SenderMailboxID:     senderMailboxID,
		SenderEncryptionKey: hex.EncodeToString(senderEncryptionKey),
	}, mailboxID, senderMailboxID, senderEncryptionKey, recipientEncryptionKey)
}

func WrapDeliveryReceipt(
	inner EncryptedMessage,
	mailboxID string,
	senderMailboxID string,
	senderEncryptionKey []byte,
	recipientEncryptionKey []byte,
) (*MailboxEnvelope, error) {
	return wrapForMailbox(MailboxPayload{
		Kind:                "delivery_receipt",
		Envelope:            inner,
		SenderMailboxID:     senderMailboxID,
		SenderEncryptionKey: hex.EncodeToString(senderEncryptionKey),
	}, mailboxID, senderMailboxID, senderEncryptionKey, recipientEncryptionKey)
}

func wrapForMailbox(
	content MailboxPayload,
	mailboxID string,
	senderMailboxID string,
	senderEncryptionKey []byte,
	recipientEncryptionKey []byte,
) (*MailboxEnvelope, error) {
	if err := ValidateMailboxID(mailboxID); err != nil {
		return nil, err
	}
	if err := ValidateMailboxID(senderMailboxID); err != nil {
		return nil, fmt.Errorf("invalid sender mailbox identifier: %w", err)
	}
	if len(senderEncryptionKey) != 32 || len(recipientEncryptionKey) != 32 {
		return nil, fmt.Errorf("invalid encryption key size")
	}
	recipientKey, err := ecdh.X25519().NewPublicKey(recipientEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient encryption key: %w", err)
	}
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mailbox ephemeral key: %w", err)
	}
	shared, err := ephemeral.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("derive mailbox key: %w", err)
	}
	id, err := NewMailboxID()
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("marshal mailbox payload: %w", err)
	}
	padded, err := padMailboxPayload(payload)
	if err != nil {
		return nil, err
	}
	key := deriveMailboxKey(shared, mailboxID, id)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("create mailbox cipher: %w", err)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate mailbox nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, padded, mailboxAssociatedData(mailboxID, id))
	return &MailboxEnvelope{
		ID:                 id,
		MailboxID:          mailboxID,
		EphemeralPublicKey: hex.EncodeToString(ephemeral.PublicKey().Bytes()),
		Nonce:              nonce,
		Ciphertext:         ciphertext,
	}, nil
}

// Open decrypts the outer mailbox layer and authenticates its mailbox ID.
func (envelope *MailboxEnvelope) Open(
	recipientEncryptionPrivateKey []byte,
	expectedMailboxID string,
) (*MailboxPayload, error) {
	if err := envelope.Validate(); err != nil {
		return nil, err
	}
	if !strings.EqualFold(envelope.MailboxID, expectedMailboxID) {
		return nil, fmt.Errorf("mailbox address mismatch")
	}
	if len(recipientEncryptionPrivateKey) != 32 {
		return nil, fmt.Errorf("invalid recipient encryption private key")
	}
	ephemeralBytes, err := hex.DecodeString(envelope.EphemeralPublicKey)
	if err != nil || len(ephemeralBytes) != 32 {
		return nil, fmt.Errorf("invalid mailbox ephemeral key")
	}
	if len(envelope.Nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid mailbox nonce")
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(recipientEncryptionPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient encryption private key: %w", err)
	}
	ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid mailbox ephemeral key: %w", err)
	}
	shared, err := privateKey.ECDH(ephemeralKey)
	if err != nil {
		return nil, fmt.Errorf("derive mailbox key: %w", err)
	}
	aead, err := chacha20poly1305.New(deriveMailboxKey(shared, envelope.MailboxID, envelope.ID))
	if err != nil {
		return nil, fmt.Errorf("create mailbox cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext,
		mailboxAssociatedData(envelope.MailboxID, envelope.ID))
	if err != nil {
		return nil, fmt.Errorf("authenticate mailbox payload: %w", err)
	}
	payloadBytes, err := unpadMailboxPayload(plaintext)
	if err != nil {
		return nil, err
	}
	var payload MailboxPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal mailbox payload: %w", err)
	}
	if payload.Kind != "message" && payload.Kind != "delivery_receipt" {
		return nil, fmt.Errorf("unknown mailbox payload kind")
	}
	if err := ValidateMailboxID(payload.SenderMailboxID); err != nil {
		return nil, fmt.Errorf("invalid sender mailbox identifier: %w", err)
	}
	senderEncryptionKey, err := hex.DecodeString(payload.SenderEncryptionKey)
	if err != nil || len(senderEncryptionKey) != 32 {
		return nil, fmt.Errorf("invalid sender encryption key")
	}
	return &payload, nil
}

func deriveMailboxKey(shared []byte, mailboxID, envelopeID string) []byte {
	hash := sha256.New()
	hash.Write([]byte(mailboxLabel))
	hash.Write(shared)
	hash.Write([]byte(mailboxID))
	hash.Write([]byte(envelopeID))
	return hash.Sum(nil)
}

func mailboxAssociatedData(mailboxID, envelopeID string) []byte {
	return []byte(mailboxLabel + "|" + mailboxID + "|" + envelopeID)
}

func padMailboxPayload(payload []byte) ([]byte, error) {
	if len(payload)+4 > maxMailboxPayload {
		return nil, fmt.Errorf("mailbox payload exceeds size limit")
	}
	targetSize := ((len(payload) + 4 + mailboxPaddingSize - 1) / mailboxPaddingSize) * mailboxPaddingSize
	padded := make([]byte, targetSize)
	copy(padded, payload)
	if _, err := io.ReadFull(rand.Reader, padded[len(payload):targetSize-4]); err != nil {
		return nil, fmt.Errorf("pad mailbox payload: %w", err)
	}
	binary.BigEndian.PutUint32(padded[targetSize-4:], uint32(len(payload)))
	return padded, nil
}

func unpadMailboxPayload(padded []byte) ([]byte, error) {
	if len(padded) < 4 || len(padded) > maxMailboxPayload || len(padded)%mailboxPaddingSize != 0 {
		return nil, fmt.Errorf("invalid padded mailbox payload")
	}
	payloadSize := int(binary.BigEndian.Uint32(padded[len(padded)-4:]))
	if payloadSize <= 0 || payloadSize > len(padded)-4 {
		return nil, fmt.Errorf("invalid mailbox payload size")
	}
	return bytes.Clone(padded[:payloadSize]), nil
}
