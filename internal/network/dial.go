package network

// dial.go owns the ghost connection lifecycle (SPEC section 10):
//
//	RESOLVE -> DIAL -> HANDSHAKE -> KEY ESTABLISHMENT -> EXCHANGE -> CLOSE
//
// Nothing here is user-managed. A connection exists only for the duration of
// one exchange and is destroyed immediately afterwards.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

// PeerStore is the slice of the database the network layer needs in order to
// remember authenticated identities and their temporary routes.
//
// It is deliberately satisfied by *database.Database but kept as an interface
// so the network layer does not depend on the concrete storage engine.
type PeerStore interface {
	// RecordPeerIdentityWithKey stores an authenticated peer identity
	// together with the peer's published X25519 encryption key.
	RecordPeerIdentityWithKey(
		namespace string,
		publicKey []byte,
		encryptionPublicKey []byte,
	) error

	// StoreRoute records a temporary route with an absolute expiry time.
	StoreRoute(
		namespace string,
		publicKey []byte,
		address string,
		expiresAt int64,
	) error
}

// remoteAddress returns the peer address of an outbound session, if any.
func (s *Session) remoteAddress() string {
	if s.Conn == nil || s.Conn.RemoteAddr() == nil {
		return ""
	}

	return s.Conn.RemoteAddr().String()
}

// negotiateAsInitiator performs HELLO / HELLO_ACK on an outbound connection.
func negotiateAsInitiator(
	conn net.Conn,
	local *identity.Identity,
) (*Session, error) {
	localHello, ephemeral, err := newHello(local)
	if err != nil {
		return nil, err
	}

	data, err := json.Marshal(localHello)
	if err != nil {
		return nil, fmt.Errorf(
			"marshal hello: %w",
			err,
		)
	}

	if err := writeFrame(conn, data); err != nil {
		return nil, fmt.Errorf(
			"send hello: %w",
			err,
		)
	}

	response, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf(
			"read hello ack: %w",
			err,
		)
	}

	var envelope Message

	if err := json.Unmarshal(response, &envelope); err != nil {
		return nil, fmt.Errorf(
			"unmarshal hello ack: %w",
			err,
		)
	}

	if envelope.Type != messageTypeHelloAck {
		return nil, fmt.Errorf(
			"unexpected handshake response %q",
			envelope.Type,
		)
	}

	var peerHello handshakeHello

	if err := json.Unmarshal(envelope.Data, &peerHello); err != nil {
		return nil, fmt.Errorf(
			"unmarshal peer hello: %w",
			err,
		)
	}

	session := &Session{Conn: conn}

	if err := finishHandshake(
		session,
		true,
		ephemeral,
		localHello,
		&peerHello,
	); err != nil {
		return nil, err
	}

	return session, nil
}

// negotiateAsResponder performs HELLO / HELLO_ACK on an inbound connection.
func negotiateAsResponder(
	conn net.Conn,
	local *identity.Identity,
) (*Session, error) {
	data, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf(
			"read hello: %w",
			err,
		)
	}

	var peerHello handshakeHello

	if err := json.Unmarshal(data, &peerHello); err != nil {
		return nil, fmt.Errorf(
			"unmarshal hello: %w",
			err,
		)
	}

	localHello, ephemeral, err := newHello(local)
	if err != nil {
		return nil, err
	}

	ackData, err := json.Marshal(localHello)
	if err != nil {
		return nil, fmt.Errorf(
			"marshal hello ack: %w",
			err,
		)
	}

	ack, err := json.Marshal(Message{
		Type: messageTypeHelloAck,
		Data: ackData,
	})
	if err != nil {
		return nil, fmt.Errorf(
			"marshal hello ack envelope: %w",
			err,
		)
	}

	if err := writeFrame(conn, ack); err != nil {
		return nil, fmt.Errorf(
			"send hello ack: %w",
			err,
		)
	}

	session := &Session{Conn: conn}

	if err := finishHandshake(
		session,
		false,
		ephemeral,
		localHello,
		&peerHello,
	); err != nil {
		return nil, err
	}

	return session, nil
}

// recordPeer remembers an authenticated peer identity and, when the peer's
// transport address is known, a short-lived direct route (SPEC section 15).
func recordPeer(
	db PeerStore,
	session *Session,
	address string,
) {
	if db == nil || session.Peer == nil {
		return
	}

	_ = db.RecordPeerIdentityWithKey(
		session.PeerNamespace,
		[]byte(session.Peer),
		session.PeerEncryptionKey,
	)

	if address == "" {
		return
	}

	_ = db.StoreRoute(
		session.PeerNamespace,
		[]byte(session.Peer),
		address,
		time.Now().Add(DefaultRouteTTL).Unix(),
	)
}

func recordOutboundPeer(
	db PeerStore,
	session *Session,
) {
	recordPeer(db, session, session.remoteAddress())
}

func recordInboundPeer(
	db PeerStore,
	session *Session,
	address string,
) {
	recordPeer(db, session, address)
}

// Dial opens a temporary authenticated, encrypted connection to address.
//
// The caller must Close the returned session as soon as the exchange is
// complete; session keys are destroyed on Close (SPEC section 33).
func Dial(
	address string,
	local *identity.Identity,
	db PeerStore,
) (*Session, error) {
	conn, err := net.DialTimeout(
		"tcp",
		address,
		dialTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"dial %s: %w",
			address,
			err,
		)
	}

	if err := conn.SetDeadline(
		time.Now().Add(sessionTimeout),
	); err != nil {
		_ = conn.Close()

		return nil, err
	}

	session, err := negotiateAsInitiator(conn, local)
	if err != nil {
		_ = conn.Close()

		return nil, err
	}

	recordOutboundPeer(db, session)

	return session, nil
}

// PeerKey returns the authenticated Ed25519 key of the session peer.
func (s *Session) PeerKey() ed25519.PublicKey {
	return s.Peer
}
