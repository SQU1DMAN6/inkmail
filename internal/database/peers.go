package database

// peers.go: friendly peer management (aliases, Peer ID parsing, removal).

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

// MaxAliasLength bounds friendly peer names.
const MaxAliasLength = 32

var aliasPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_-]{0,31}$`)

// reservedAliases cannot be used as peer aliases (folders / commands).
var reservedAliases = map[string]struct{}{
	"all": {}, "inbox": {}, "archive": {}, "important": {}, "deleted": {},
	"msg": {}, "peers": {}, "relays": {}, "send": {}, "open": {},
	"help": {}, "quit": {}, "exit": {}, "identity": {}, "list": {},
	"add": {}, "remove": {}, "alias": {}, "daddy": {},
}

// ValidateAlias checks a friendly peer name without touching the database.
func ValidateAlias(alias string) error {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return fmt.Errorf("alias cannot be empty")
	}
	if len(alias) > MaxAliasLength {
		return fmt.Errorf("alias cannot exceed %d characters", MaxAliasLength)
	}
	if _, err := strconv.Atoi(alias); err == nil {
		return fmt.Errorf("alias cannot be purely numeric (collides with peer numbers)")
	}
	if strings.Contains(alias, "::") {
		return fmt.Errorf("alias cannot contain %q", "::")
	}
	if !aliasPattern.MatchString(alias) {
		return fmt.Errorf("alias must start with letter/digit/underscore, only letters/digits/'_'/'-' (max %d)", MaxAliasLength)
	}
	if _, reserved := reservedAliases[strings.ToLower(alias)]; reserved {
		return fmt.Errorf("alias %q is reserved; pick another name", alias)
	}
	return nil
}

// ParsePeerID parses "<namespace>::<full-ed25519-pubkey-hex>".
// `peers add` requires the FULL key (64 hex chars). Short fingerprints are
// rejected: they cannot encrypt or verify, so they must never be added.
func ParsePeerID(raw string) (string, []byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil, fmt.Errorf("peer ID cannot be empty (expected namespace::full-public-key)")
	}
	parts := strings.Split(raw, "::")
	if len(parts) != 2 {
		return "", nil, fmt.Errorf("invalid peer ID %q: expected namespace::public-key-hex", raw)
	}
	namespace := strings.TrimSpace(parts[0])
	keyHex := strings.TrimSpace(strings.ToLower(parts[1]))
	if err := identity.ValidateNamespace(namespace); err != nil {
		return "", nil, fmt.Errorf("invalid peer namespace: %w", err)
	}
	if keyHex == "" {
		return "", nil, fmt.Errorf("peer ID %q has no public key", raw)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", nil, fmt.Errorf("invalid peer public key hex: %w", err)
	}
	if len(key) != ed25519.PublicKeySize {
		if len(key) == 8 {
			return "", nil, fmt.Errorf(
				"peer ID %q uses a short fingerprint; `peers add` needs the FULL 64-hex-char public key",
				raw,
			)
		}
		return "", nil, fmt.Errorf(
			"invalid peer public key length: got %d bytes, want %d (64 hex chars)",
			len(key),
			ed25519.PublicKeySize,
		)
	}
	return namespace, key, nil
}

// GetPeerByAlias returns the peer with the given name (case-insensitive).
func (d *Database) GetPeerByAlias(alias string) (*PeerIdentity, error) {
	alias = strings.TrimSpace(alias)
	if alias == "" {
		return nil, fmt.Errorf("alias cannot be empty")
	}
	var peer PeerIdentity
	var encryptionKey []byte
	err := d.DB.QueryRow(`
		SELECT namespace, public_key, encryption_public_key, alias, first_seen, last_seen
		FROM peer_identities
		WHERE alias = ? COLLATE NOCASE
	`, alias).Scan(
		&peer.Namespace,
		&peer.PublicKey,
		&encryptionKey,
		&peer.Alias,
		&peer.FirstSeen,
		&peer.LastSeen,
	)
	if err != nil {
		return nil, fmt.Errorf("peer alias %q not found", alias)
	}
	peer.EncryptionPublicKey = encryptionKey
	return &peer, nil
}
