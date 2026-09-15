package network

// handshake.go implements the InkMail v2 authenticated handshake.
//
// The handshake retains the original HELLO / HELLO_ACK exchange but extends
// it so that it provides, in one round trip (SPEC section 32):
//
//   - authentication: both sides prove ownership of their Ed25519 key
//   - key agreement: both sides contribute an ephemeral X25519 public key
//   - session encryption: a pair of directional transport keys
//
// The long-term Ed25519 identity key is never used to encrypt traffic. It
// only signs the handshake transcript (SPEC section 33).

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// handshakeHello is the JSON body of HELLO and HELLO_ACK.
type handshakeHello struct {
	Version       int    `json:"version"`
	Namespace     string `json:"namespace"`
	PublicKey     string `json:"public_key"`
	EncryptionKey string `json:"encryption_key"`
	EphemeralKey  string `json:"ephemeral_key"`
	Timestamp     int64  `json:"timestamp"`
	Signature     string `json:"signature"`
}

// transcriptBytes returns the canonical bytes that a handshake signature
// covers. It is domain-separated and binds every field.
func (h *handshakeHello) transcriptBytes() []byte {
	return []byte(fmt.Sprintf(
		"%s|%d|%s|%s|%s|%s|%d",
		handshakeLabel,
		h.Version,
		h.Namespace,
		h.PublicKey,
		h.EncryptionKey,
		h.EphemeralKey,
		h.Timestamp,
	))
}

// newHello builds a signed handshake message with a fresh ephemeral key.
func newHello(
	local *identity.Identity,
) (*handshakeHello, *ecdh.PrivateKey, error) {
	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf(
			"generate ephemeral key: %w",
			err,
		)
	}

	hello := &handshakeHello{
		Version:       protocolVersion,
		Namespace:     local.Namespace,
		PublicKey:     hex.EncodeToString(local.PublicKey),
		EncryptionKey: hex.EncodeToString(local.EncryptionPublicKey),
		EphemeralKey: hex.EncodeToString(
			ephemeral.PublicKey().Bytes(),
		),
		Timestamp: time.Now().Unix(),
	}

	hello.Signature = hex.EncodeToString(
		ed25519.Sign(
			local.PrivateKey,
			hello.transcriptBytes(),
		),
	)

	return hello, ephemeral, nil
}

// verifyHello authenticates a handshake message and returns the peer's keys.
func verifyHello(
	hello *handshakeHello,
) (
	ed25519.PublicKey,
	[]byte,
	*ecdh.PublicKey,
	error,
) {
	if hello.Version != protocolVersion {
		return nil, nil, nil, fmt.Errorf(
			"unsupported protocol version %d",
			hello.Version,
		)
	}

	if err := identity.ValidateNamespace(hello.Namespace); err != nil {
		return nil, nil, nil, fmt.Errorf(
			"invalid peer namespace: %w",
			err,
		)
	}

	peerKey, err := hex.DecodeString(hello.PublicKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"decode peer public key: %w",
			err,
		)
	}

	if len(peerKey) != ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf(
			"peer public key has invalid size",
		)
	}

	peerEncryptionKey, err := hex.DecodeString(
		hello.EncryptionKey,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"decode peer encryption key: %w",
			err,
		)
	}

	if len(peerEncryptionKey) != 32 {
		return nil, nil, nil, fmt.Errorf(
			"peer encryption key has invalid size",
		)
	}

	ephemeralBytes, err := hex.DecodeString(
		hello.EphemeralKey,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"decode peer ephemeral key: %w",
			err,
		)
	}

	ephemeral, err := ecdh.X25519().NewPublicKey(
		ephemeralBytes,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"invalid peer ephemeral key: %w",
			err,
		)
	}

	signature, err := hex.DecodeString(hello.Signature)
	if err != nil {
		return nil, nil, nil, fmt.Errorf(
			"decode handshake signature: %w",
			err,
		)
	}

	if !ed25519.Verify(
		ed25519.PublicKey(peerKey),
		hello.transcriptBytes(),
		signature,
	) {
		return nil, nil, nil, fmt.Errorf(
			"handshake signature verification failed",
		)
	}

	skew := time.Since(
		time.Unix(hello.Timestamp, 0),
	)

	if skew < 0 {
		skew = -skew
	}

	if skew > maxClockSkew {
		return nil, nil, nil, fmt.Errorf(
			"handshake timestamp outside acceptable window",
		)
	}

	return ed25519.PublicKey(peerKey),
		peerEncryptionKey,
		ephemeral,
		nil
}

// deriveSessionKey expands the X25519 shared secret into one directional
// transport key, bound to the full handshake transcript.
func deriveSessionKey(
	shared []byte,
	transcript []byte,
	label string,
) ([]byte, error) {
	salt := sha256.Sum256(transcript)

	reader := hkdf.New(
		sha256.New,
		shared,
		salt[:],
		[]byte(label),
	)

	key := make([]byte, chacha20poly1305.KeySize)

	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf(
			"derive session key: %w",
			err,
		)
	}

	return key, nil
}

// installSessionKeys derives both directional transport keys from the
// ephemeral Diffie-Hellman secret and installs them on the session.
func installSessionKeys(
	session *Session,
	initiator bool,
	localEphemeral *ecdh.PrivateKey,
	peerEphemeral *ecdh.PublicKey,
	initiatorHello *handshakeHello,
	responderHello *handshakeHello,
) error {
	shared, err := localEphemeral.ECDH(peerEphemeral)
	if err != nil {
		return fmt.Errorf(
			"ephemeral key agreement failed: %w",
			err,
		)
	}

	transcript := append(
		append(
			[]byte{},
			initiatorHello.transcriptBytes()...,
		),
		responderHello.transcriptBytes()...,
	)

	initiatorKey, err := deriveSessionKey(
		shared,
		transcript,
		sessionLabelInitiator,
	)
	if err != nil {
		return err
	}

	responderKey, err := deriveSessionKey(
		shared,
		transcript,
		sessionLabelResponder,
	)
	if err != nil {
		return err
	}

	sendKey := responderKey
	recvKey := initiatorKey

	if initiator {
		sendKey = initiatorKey
		recvKey = responderKey
	}

	sendAead, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return fmt.Errorf(
			"create send cipher: %w",
			err,
		)
	}

	recvAead, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return fmt.Errorf(
			"create receive cipher: %w",
			err,
		)
	}

	session.sendAead = sendAead
	session.recvAead = recvAead
	session.sendCounter = 0
	session.recvCounter = 0

	return nil
}

// finishHandshake authenticates the peer, installs the session keys and
// records the authenticated peer information on the session.
func finishHandshake(
	session *Session,
	initiator bool,
	localEphemeral *ecdh.PrivateKey,
	localHello *handshakeHello,
	peerHello *handshakeHello,
) error {
	peerKey, peerEncryptionKey, peerEphemeral, err :=
		verifyHello(peerHello)
	if err != nil {
		return err
	}

	initiatorHello := localHello
	responderHello := peerHello

	if !initiator {
		initiatorHello = peerHello
		responderHello = localHello
	}

	if err := installSessionKeys(
		session,
		initiator,
		localEphemeral,
		peerEphemeral,
		initiatorHello,
		responderHello,
	); err != nil {
		return err
	}

	session.Peer = peerKey
	session.PeerNamespace = peerHello.Namespace
	session.PeerEncryptionKey = peerEncryptionKey

	return nil
}
