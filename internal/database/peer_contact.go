package database

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

// PeerContact is the shareable contact bundle required for private relay mail.
type PeerContact struct {
	Namespace           string
	PublicKey           []byte
	EncryptionPublicKey []byte
	MailboxID           string
}

// ParsePeerContact parses namespace::ed25519-key::x25519-key::mailbox-id.
func ParsePeerContact(raw string) (PeerContact, error) {
	parts := strings.Split(strings.TrimSpace(raw), "::")
	if len(parts) != 4 {
		return PeerContact{}, fmt.Errorf("expected namespace::ed25519-key::x25519-key::mailbox-id")
	}
	contact := PeerContact{Namespace: strings.TrimSpace(parts[0])}
	if err := identity.ValidateNamespace(contact.Namespace); err != nil {
		return PeerContact{}, fmt.Errorf("invalid contact namespace: %w", err)
	}
	var err error
	contact.PublicKey, err = hex.DecodeString(parts[1])
	if err != nil || len(contact.PublicKey) != ed25519.PublicKeySize {
		return PeerContact{}, fmt.Errorf("invalid Ed25519 public key")
	}
	contact.EncryptionPublicKey, err = hex.DecodeString(parts[2])
	if err != nil || len(contact.EncryptionPublicKey) != 32 {
		return PeerContact{}, fmt.Errorf("invalid X25519 public key")
	}
	mailboxID, err := hex.DecodeString(parts[3])
	if err != nil || len(mailboxID) != 32 {
		return PeerContact{}, fmt.Errorf("invalid opaque mailbox identifier")
	}
	contact.MailboxID = hex.EncodeToString(mailboxID)
	return contact, nil
}

// String formats a shareable contact bundle without shortening key material.
func (contact PeerContact) String() string {
	return fmt.Sprintf("%s::%s::%s::%s", contact.Namespace,
		hex.EncodeToString(contact.PublicKey),
		hex.EncodeToString(contact.EncryptionPublicKey),
		contact.MailboxID)
}
