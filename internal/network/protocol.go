package network

// protocol.go defines the InkMail wire protocol: framing, the handshake
// transcript, ephemeral session key agreement and the authenticated
// encrypted transport used by every ghost connection.
//
// Two independent encryption layers exist (SPEC section 31):
//
//   - transport encryption: protects a single TCP connection between two
//     nodes and is established by the handshake in this file
//   - end-to-end encryption: protects message subject and body from relays
//     and from Daddy and lives in internal/message
//
// Neither layer replaces the other.

import (
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

const (
	// magic prefixes every InkMail frame.
	magic = "INKM"

	// maxFrameSize bounds a single protocol frame (SPEC section 42).
	maxFrameSize = 4 * 1024 * 1024

	// protocolVersion is the InkMail v2 protocol revision.
	protocolVersion = 2

	// handshakeLabel domain-separates handshake signatures.
	handshakeLabel = "inkmail-hello-v2"

	// sessionLabelInitiator / sessionLabelResponder domain-separate the
	// directional transport keys derived during the handshake.
	sessionLabelInitiator = "inkmail-session-initiator"
	sessionLabelResponder = "inkmail-session-responder"

	// DefaultRouteTTL is how long a registered route stays usable
	// (SPEC section 9).
	DefaultRouteTTL = 5 * time.Minute

	// DefaultCleanupPeriod is how often expired held messages and expired
	// routes are removed (SPEC section 41).
	DefaultCleanupPeriod = 5 * time.Minute

	// HeldMessageTTL is the maximum lifetime of a held message in seconds
	// (30 days, SPEC section 22).
	HeldMessageTTL = 30 * 24 * 60 * 60

	// dialTimeout bounds a single ghost connection attempt.
	dialTimeout = 10 * time.Second

	// sessionTimeout bounds a whole temporary session.
	sessionTimeout = 30 * time.Second

	// handshakeTimeout bounds the handshake phase only.
	// handshakeTimeout = 15 * time.Second

	// maxClockSkew bounds how far a handshake timestamp may deviate.
	maxClockSkew = 15 * time.Minute

	// maxHeldMessageBatch bounds how many held messages a single
	// MESSAGE_DELIVERY frame may carry.
	maxHeldMessageBatch = 256
)

// Protocol message types (SPEC section 48).
const (
	messageTypeHello            = "HELLO"
	messageTypeHelloAck         = "HELLO_ACK"
	messageTypeRegisterRoute    = "REGISTER_ROUTE"
	messageTypeRegisterRouteAck = "REGISTER_ROUTE_ACK"
	messageTypeLookupRoute      = "LOOKUP_ROUTE"
	messageTypeLookupRouteAck   = "LOOKUP_ROUTE_ACK"
	messageTypeMessage          = "MESSAGE"
	messageTypeMessageAck       = "MESSAGE_ACK"
	messageTypeHoldMessage      = "HOLD_MESSAGE"
	messageTypeHoldAck          = "HOLD_ACK"
	messageTypeFetchMessages    = "FETCH_MESSAGES"
	messageTypeDelivery         = "MESSAGE_DELIVERY"
	messageTypeDeliveryAck      = "DELIVERY_ACK"
	messageTypeDeleteMessage    = "DELETE_MESSAGE"
	messageTypeDeleteAck        = "DELETE_ACK"
)

// Acknowledgement status values.
const (
	statusDelivered     = "delivered"
	statusHeld          = "held"
	statusAlreadyStored = "already_stored"
	statusRejected      = "rejected"
	statusOK            = "ok"
)

// Message is the framed envelope carried by every protocol exchange.
type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// Session is a temporary ghost connection. It is created by the handshake,
// used for a single exchange and closed immediately afterwards. The session
// keys live only for the lifetime of the Session value (SPEC section 33).
type Session struct {
	Conn net.Conn

	// Peer is the authenticated Ed25519 identity key of the remote node.
	Peer ed25519.PublicKey

	// PeerNamespace is the authenticated namespace of the remote node.
	PeerNamespace string

	// PeerEncryptionKey is the authenticated X25519 encryption key of the
	// remote node (SPEC section 32).
	PeerEncryptionKey []byte

	sendAead    cipher.AEAD
	recvAead    cipher.AEAD
	sendCounter uint64
	recvCounter uint64
}

// Encrypted reports whether the transport layer is encrypted.
func (s *Session) Encrypted() bool {
	return s.sendAead != nil && s.recvAead != nil
}

// Destroy drops the session keys from memory. It must be called once the
// connection is no longer required (SPEC section 33).
func (s *Session) Destroy() {
	s.sendAead = nil
	s.recvAead = nil
	s.sendCounter = 0
	s.recvCounter = 0
}

// Close destroys the session keys and closes the underlying connection.
func (s *Session) Close() error {
	s.Destroy()

	if s.Conn == nil {
		return nil
	}

	return s.Conn.Close()
}

// PeerFingerprint returns the display fingerprint of the authenticated peer.
func (s *Session) PeerFingerprint() string {
	if s.Peer == nil {
		return ""
	}

	return identity.Fingerprint(s.Peer)
}

// sameBytes reports whether two byte slices are identical.
//
// crypto/subtle is not used because these comparisons are over public
// material (identity keys, message IDs) that an attacker already knows.
func sameBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
