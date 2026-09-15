package message

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	maxSubjectLength = 256
	maxBodyLength    = 1024 * 1024

	// x25519PublicKeySize is the size of an X25519 public key in bytes.
	// crypto/ecdh does not expose key sizes through the Curve interface.
	x25519PublicKeySize = 32
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

// EncryptedMessage represents an end-to-end encrypted message envelope
// as specified in SPEC section 17.
// subject + body are inside the ciphertext.
type EncryptedMessage struct {
	ID                     string `json:"id"`
	SenderNamespace        string `json:"sender_namespace"`
	SenderPublicKey        string `json:"sender_public_key"`
	RecipientNamespace     string `json:"recipient_namespace"`
	RecipientPublicKey     string `json:"recipient_public_key"`
	RecipientEncryptionKey string `json:"recipient_encryption_key"`
	EphemeralPublicKey     string `json:"ephemeral_public_key"`
	Nonce                  string `json:"nonce"`
	Ciphertext             string `json:"ciphertext"`
	CreatedAt              int64  `json:"created_at"`
	Signature              string `json:"signature"`
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

// VerifyID recomputes the message ID from the stable message content and
// compares it with the ID carried in the message (SPEC section 20).
//
// Only the legitimate recipient can perform this check, because it requires
// the decrypted subject and body.
func (m *Message) VerifyID() error {
	if m.ID == "" {
		return fmt.Errorf(
			"message has no ID",
		)
	}

	expected := m.calculateID()

	if subtle.ConstantTimeCompare(
		[]byte(expected),
		[]byte(m.ID),
	) != 1 {
		return fmt.Errorf(
			"message ID does not match message content",
		)
	}

	return nil
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

// EncryptForRecipient encrypts the message subject and body for the
// specified recipient using their X25519 encryption public key.
// Returns an EncryptedMessage envelope as per SPEC section 17.
func (m *Message) EncryptForRecipient(
	recipientEncryptionKey []byte,
	recipientNamespace string,
	senderPrivateKey ed25519.PrivateKey,
) (*EncryptedMessage, error) {
	// Generate ephemeral X25519 keypair for this message
	ephemeralPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key: %w", err)
	}

	// Validate and import the recipient's X25519 public key
	recipientKey, err := ecdh.X25519().NewPublicKey(
		recipientEncryptionKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid recipient encryption key: %w",
			err,
		)
	}

	// Derive shared secret using X25519 ECDH
	sharedSecret, err := ephemeralPriv.ECDH(recipientKey)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	// Derive encryption key using SHA-256
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte(m.ID))
	derivedKey := h.Sum(nil)

	// Use ChaCha20-Poly1305 for encryption
	ae, err := chacha20poly1305.New(derivedKey[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	// Create nonce
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt subject and body together (SPEC section 18)
	plaintext := m.Subject + "\n" + m.Body
	ciphertext := ae.Seal(nil, nonce, []byte(plaintext), nil)

	// Create encrypted envelope
	encMsg := &EncryptedMessage{
		ID:                     m.ID,
		SenderNamespace:        m.SenderNamespace,
		SenderPublicKey:        m.SenderPublicKey,
		RecipientNamespace:     recipientNamespace,
		RecipientPublicKey:     m.RecipientPublicKey,
		RecipientEncryptionKey: hex.EncodeToString(recipientEncryptionKey),
		EphemeralPublicKey:     hex.EncodeToString(ephemeralPub),
		Nonce:                  hex.EncodeToString(nonce),
		Ciphertext:             hex.EncodeToString(ciphertext),
		CreatedAt:              m.CreatedAt,
	}

	// Sign the encrypted envelope (SPEC section 19)
	encMsg.Signature = encMsg.calculateSignature(senderPrivateKey)

	return encMsg, nil
}

// DecryptFromSender decrypts an EncryptedMessage using the recipient's
// X25519 private key and verifies the sender's signature.
func (em *EncryptedMessage) DecryptFromSender(
	recipientEncryptionPrivateKey []byte,
	recipientNamespace string,
) (*Message, error) {
	// Verify signature first (SPEC section 19)
	if err := em.Verify(); err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}

	// Decode keys
	senderPublic, err := hex.DecodeString(em.SenderPublicKey)
	if err != nil || len(senderPublic) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid sender public key")
	}

	ephemeralPublic, err := hex.DecodeString(em.EphemeralPublicKey)
	if err != nil ||
		len(ephemeralPublic) != x25519PublicKeySize {
		return nil, fmt.Errorf("invalid ephemeral public key")
	}

	nonce, err := hex.DecodeString(em.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("invalid nonce")
	}

	ciphertext, err := hex.DecodeString(em.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("invalid ciphertext")
	}

	// Import the recipient's X25519 private key
	recipientPrivateKey, err := ecdh.X25519().NewPrivateKey(
		recipientEncryptionPrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid recipient encryption private key: %w",
			err,
		)
	}

	// Import the sender's ephemeral X25519 public key
	ephemeralPublicKey, err := ecdh.X25519().NewPublicKey(
		ephemeralPublic,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"invalid ephemeral public key: %w",
			err,
		)
	}

	// Derive shared secret
	sharedSecret, err := recipientPrivateKey.ECDH(
		ephemeralPublicKey,
	)
	if err != nil {
		return nil, fmt.Errorf("derive shared secret: %w", err)
	}

	// Derive encryption key (must match sender's derivation)
	h := sha256.New()
	h.Write(sharedSecret)
	h.Write([]byte(em.ID))
	derivedKey := h.Sum(nil)

	// Decrypt
	ae, err := chacha20poly1305.New(derivedKey[:chacha20poly1305.KeySize])
	if err != nil {
		return nil, fmt.Errorf("create AEAD: %w", err)
	}

	plaintext, err := ae.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	// Split subject and body
	parts := strings.SplitN(string(plaintext), "\n", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid decrypted message format")
	}

	msg := &Message{
		ID:                 em.ID,
		SenderNamespace:    em.SenderNamespace,
		SenderPublicKey:    em.SenderPublicKey,
		RecipientNamespace: recipientNamespace,
		RecipientPublicKey: em.RecipientPublicKey,
		Subject:            parts[0],
		Body:               parts[1],
		CreatedAt:          em.CreatedAt,
	}

	return msg, nil
}

func (em *EncryptedMessage) calculateSignature(
	signerPrivateKey ed25519.PrivateKey,
) string {
	signature := ed25519.Sign(
		signerPrivateKey,
		em.signingBytes(),
	)
	return hex.EncodeToString(signature)
}

func (em *EncryptedMessage) signingBytes() []byte {
	type unsignedEncryptedMessage struct {
		ID                     string `json:"id"`
		SenderNamespace        string `json:"sender_namespace"`
		SenderPublicKey        string `json:"sender_public_key"`
		RecipientNamespace     string `json:"recipient_namespace"`
		RecipientPublicKey     string `json:"recipient_public_key"`
		RecipientEncryptionKey string `json:"recipient_encryption_key"`
		EphemeralPublicKey     string `json:"ephemeral_public_key"`
		Nonce                  string `json:"nonce"`
		Ciphertext             string `json:"ciphertext"`
		CreatedAt              int64  `json:"created_at"`
	}

	data, _ := json.Marshal(unsignedEncryptedMessage{
		ID:                     em.ID,
		SenderNamespace:        em.SenderNamespace,
		SenderPublicKey:        em.SenderPublicKey,
		RecipientNamespace:     em.RecipientNamespace,
		RecipientPublicKey:     em.RecipientPublicKey,
		RecipientEncryptionKey: em.RecipientEncryptionKey,
		EphemeralPublicKey:     em.EphemeralPublicKey,
		Nonce:                  em.Nonce,
		Ciphertext:             em.Ciphertext,
		CreatedAt:              em.CreatedAt,
	})

	return data
}

// ValidateID checks that the message ID is well formed. Relays and Daddy can
// only verify the shape of the ID, because the value is derived from the
// encrypted payload they are not permitted to read (SPEC section 20).
func (em *EncryptedMessage) ValidateID() error {
	decoded, err := hex.DecodeString(em.ID)
	if err != nil {
		return fmt.Errorf(
			"invalid message ID",
		)
	}

	if len(decoded) != sha256.Size {
		return fmt.Errorf(
			"invalid message ID length",
		)
	}

	return nil
}

func (em *EncryptedMessage) Verify() error {
	if em.ID == "" {
		return fmt.Errorf("message has no ID")
	}

	if err := em.ValidateID(); err != nil {
		return err
	}

	if err := identity.ValidateNamespace(em.SenderNamespace); err != nil {
		return fmt.Errorf("invalid sender namespace: %w", err)
	}

	if err := identity.ValidateNamespace(em.RecipientNamespace); err != nil {
		return fmt.Errorf("invalid recipient namespace: %w", err)
	}

	senderPublic, err := hex.DecodeString(em.SenderPublicKey)
	if err != nil || len(senderPublic) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid sender public key")
	}

	signature, err := hex.DecodeString(em.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid signature")
	}

	if !ed25519.Verify(
		ed25519.PublicKey(senderPublic),
		em.signingBytes(),
		signature,
	) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
