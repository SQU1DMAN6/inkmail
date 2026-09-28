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
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

const (
	// magic prefixes every InkMail frame.
	magic = "INKM"

	// maxFrameSize bounds a single protocol frame (SPEC section 42).
	maxFrameSize          = 4 * 1024 * 1024
	maxHandshakeFrameSize = 64 * 1024

	// protocolVersion 4 binds anonymous-session status into the signed handshake.
	protocolVersion = 4

	// handshakeLabel domain-separates handshake signatures.
	handshakeLabel = "inkmail-hello-v4"

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
)

var (
	// DefaultDialTimeout bounds a single ghost connection attempt (SPEC v0.5
	// section 16). 3s keeps an unreachable direct route from stalling the
	// user's send operation. Override with INKMAIL_DIAL_TIMEOUT (e.g. "5s").
	DefaultDialTimeout = 3 * time.Second

	// DefaultSessionTimeout bounds a whole temporary ghost session
	// (handshake + one exchange + ack). 10s is enough for a healthy peer or
	// Daddy while still failing fast.
	DefaultSessionTimeout = 10 * time.Second
)

// effectiveDialTimeout returns the per-attempt timeout, honouring
// INKMAIL_DIAL_TIMEOUT when set to a valid duration.
func effectiveDialTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("INKMAIL_DIAL_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 &&
			parsed <= time.Minute {
			return parsed
		}
	}

	return DefaultDialTimeout
}

// effectiveSessionTimeout returns the whole-session deadline, honouring
// INKMAIL_SESSION_TIMEOUT when set to a valid duration.
func effectiveSessionTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("INKMAIL_SESSION_TIMEOUT")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 &&
			parsed <= 5*time.Minute {
			return parsed
		}
	}

	return DefaultSessionTimeout
}

const (

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
	messageTypeDeleteAck        = "DELETE_ACK"
	messageTypeRelayProbe       = "RELAY_PROBE"
	messageTypeRelayProbeAck    = "RELAY_PROBE_ACK"
	messageTypeGhostForward     = "GHOST_FORWARD"
	messageTypeGhostForwardAck  = "GHOST_FORWARD_ACK"
)

// Acknowledgement status values.
const (
	statusDelivered     = "delivered"
	statusHeld          = "held"
	statusAlreadyStored = "already_stored"
	statusRejected      = "rejected"
	statusOK            = "ok"
	statusSynced        = "synced"
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

	// MailboxID is the single mailbox scope this session is allowed to operate
	// within. Privileged Daddy operations must all target the same mailbox.
	MailboxID       string
	fetchedMessages map[string]string

	// Peer is the authenticated Ed25519 identity key of the remote node.
	Peer ed25519.PublicKey

	// PeerNamespace is the authenticated namespace of the remote node.
	PeerNamespace string
	PeerAnonymous bool

	// PeerEncryptionKey is the authenticated X25519 encryption key of the
	// remote node (SPEC section 32).
	PeerEncryptionKey []byte

	sendAead    cipher.AEAD
	recvAead    cipher.AEAD
	sendCounter uint64
	recvCounter uint64
}

func (s *Session) Encrypted() bool {
	return s.sendAead != nil && s.recvAead != nil
}

func (s *Session) Destroy() {
	s.sendAead = nil
	s.recvAead = nil
	s.sendCounter = 0
	s.recvCounter = 0
}

func (s *Session) Close() error {
	s.Destroy()

	if s.Conn == nil {
		return nil
	}

	return s.Conn.Close()
}

func (s *Session) PeerFingerprint() string {
	if s.Peer == nil {
		return ""
	}

	return identity.Fingerprint(s.Peer)
}

func (s *Session) authorizeMailboxID(mailboxID string) error {
	if err := message.ValidateMailboxID(mailboxID); err != nil {
		return fmt.Errorf("invalid mailbox identifier: %w", err)
	}

	mailboxID = strings.TrimSpace(mailboxID)
	if s.MailboxID == "" {
		s.MailboxID = mailboxID
		return nil
	}
	if !strings.EqualFold(s.MailboxID, mailboxID) {
		return fmt.Errorf("session mailbox mismatch: session bound to %s, request targeted %s", s.MailboxID, mailboxID)
	}

	return nil
}

func (s *Session) recordFetchedMessage(messageID, mailboxID string) {
	if s.fetchedMessages == nil {
		s.fetchedMessages = make(map[string]string)
	}
	s.fetchedMessages[messageID] = mailboxID
}

func (s *Session) consumeFetchedMessage(messageID, mailboxID string) bool {
	if s.fetchedMessages[messageID] != mailboxID {
		return false
	}
	delete(s.fetchedMessages, messageID)
	return true
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
