package network

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

const (
	magic        = "IML1"
	maxFrameSize = 1024 * 1024
	protocol     = 1

	handshakeTag = "INKMAIL-HANDSHAKE-V1"

	connectionTimeout = 10 * time.Second
)

type Message struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type Hello struct {
	Version   int    `json:"version"`
	Namespace string `json:"namespace"`
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
}

type HelloAck struct {
	Version   int    `json:"version"`
	Namespace string `json:"namespace"`
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type Session struct {
	Conn          net.Conn
	Peer          ed25519.PublicKey
	PeerNamespace string
}

func writeFrame(
	conn net.Conn,
	payload []byte,
) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf(
			"frame too large",
		)
	}

	if _, err := conn.Write(
		[]byte(magic),
	); err != nil {
		return err
	}

	var length [4]byte

	binary.BigEndian.PutUint32(
		length[:],
		uint32(len(payload)),
	)

	if _, err := conn.Write(length[:]); err != nil {
		return err
	}

	_, err := conn.Write(payload)

	return err
}

func readFrame(
	conn net.Conn,
) ([]byte, error) {
	header := make([]byte, 8)

	if _, err := io.ReadFull(
		conn,
		header,
	); err != nil {
		return nil, err
	}

	if string(header[:4]) != magic {
		return nil, fmt.Errorf(
			"invalid protocol magic",
		)
	}

	length := binary.BigEndian.Uint32(
		header[4:],
	)

	if length > maxFrameSize {
		return nil, fmt.Errorf(
			"frame too large",
		)
	}

	payload := make([]byte, length)

	if _, err := io.ReadFull(
		conn,
		payload,
	); err != nil {
		return nil, err
	}

	return payload, nil
}

func sendMessage(
	conn net.Conn,
	msg Message,
) error {
	payload, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	return writeFrame(
		conn,
		payload,
	)
}

func receiveMessage(
	conn net.Conn,
	msg *Message,
) error {
	payload, err := readFrame(conn)
	if err != nil {
		return err
	}

	return json.Unmarshal(
		payload,
		msg,
	)
}

func createHello(
	local *identity.Identity,
) (Hello, []byte, error) {
	nonce := make([]byte, 32)

	if _, err := rand.Read(nonce); err != nil {
		return Hello{}, nil, err
	}

	hello := Hello{
		Version:   protocol,
		Namespace: local.Namespace,
		PublicKey: hex.EncodeToString(
			local.PublicKey,
		),
		Nonce: hex.EncodeToString(nonce),
	}

	return hello, nonce, nil
}

func handshakePayload(
	signerNamespace string,
	peerNamespace string,
	localNamespace string,
	peerPublic []byte,
	localPublic []byte,
	peerNonce []byte,
	localNonce []byte,
) []byte {
	payload := make([]byte, 0)

	appendField := func(field []byte) {
		var length [4]byte

		binary.BigEndian.PutUint32(
			length[:],
			uint32(len(field)),
		)

		payload = append(
			payload,
			length[:]...,
		)

		payload = append(
			payload,
			field...,
		)
	}

	appendField([]byte(handshakeTag))
	appendField([]byte(signerNamespace))
	appendField([]byte(peerNamespace))
	appendField([]byte(localNamespace))
	appendField(peerPublic)
	appendField(localPublic)
	appendField(peerNonce)
	appendField(localNonce)

	return payload
}

func signHandshake(
	local *identity.Identity,
	peerNamespace string,
	peerPublic []byte,
	peerNonce []byte,
	localNonce []byte,
) []byte {
	data := handshakePayload(
		local.Namespace,
		peerNamespace,
		local.Namespace,
		peerPublic,
		local.PublicKey,
		peerNonce,
		localNonce,
	)

	return ed25519.Sign(
		local.PrivateKey,
		data,
	)
}

func verifyHandshake(
	peerNamespace string,
	localNamespace string,
	peerPublic []byte,
	localPublic []byte,
	peerNonce []byte,
	localNonce []byte,
	signature []byte,
) bool {
	data := handshakePayload(
		peerNamespace,
		localNamespace,
		peerNamespace,
		localPublic,
		peerPublic,
		localNonce,
		peerNonce,
	)

	return ed25519.Verify(
		ed25519.PublicKey(peerPublic),
		data,
		signature,
	)
}

func makeAck(
	local *identity.Identity,
	peerNamespace string,
	peerPublic []byte,
	peerNonce []byte,
	localNonce []byte,
) HelloAck {
	signature := signHandshake(
		local,
		peerNamespace,
		peerPublic,
		peerNonce,
		localNonce,
	)

	return HelloAck{
		Version:   protocol,
		Namespace: local.Namespace,
		PublicKey: hex.EncodeToString(
			local.PublicKey,
		),
		Nonce: hex.EncodeToString(
			localNonce,
		),
		Signature: hex.EncodeToString(
			signature,
		),
	}
}

func performHandshake(
	conn net.Conn,
	local *identity.Identity,
) ([]byte, string, error) {
	localHello, localNonce, err := createHello(local)
	if err != nil {
		return nil, "", err
	}

	helloData, err := json.Marshal(
		localHello,
	)
	if err != nil {
		return nil, "", err
	}

	if err := sendMessage(
		conn,
		Message{
			Type: "HELLO",
			Data: helloData,
		},
	); err != nil {
		return nil, "", err
	}

	var incoming Message

	if err := receiveMessage(
		conn,
		&incoming,
	); err != nil {
		return nil, "", err
	}

	if incoming.Type != "HELLO" {
		return nil, "", fmt.Errorf(
			"expected HELLO, got %q",
			incoming.Type,
		)
	}

	var peerHello Hello

	if err := json.Unmarshal(
		incoming.Data,
		&peerHello,
	); err != nil {
		return nil, "", err
	}

	if peerHello.Version != protocol {
		return nil, "", fmt.Errorf(
			"unsupported protocol version %d",
			peerHello.Version,
		)
	}

	if err := identity.ValidateNamespace(
		peerHello.Namespace,
	); err != nil {
		return nil, "", fmt.Errorf(
			"invalid peer namespace: %w",
			err,
		)
	}

	peerPublic, err := hex.DecodeString(
		peerHello.PublicKey,
	)
	if err != nil ||
		len(peerPublic) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf(
			"invalid peer public key",
		)
	}

	peerNonce, err := hex.DecodeString(
		peerHello.Nonce,
	)
	if err != nil || len(peerNonce) != 32 {
		return nil, "", fmt.Errorf(
			"invalid peer nonce",
		)
	}

	ack := makeAck(
		local,
		peerHello.Namespace,
		peerPublic,
		peerNonce,
		localNonce,
	)

	ackData, err := json.Marshal(ack)
	if err != nil {
		return nil, "", err
	}

	if err := sendMessage(
		conn,
		Message{
			Type: "HELLO_ACK",
			Data: ackData,
		},
	); err != nil {
		return nil, "", err
	}

	var incomingAck Message

	if err := receiveMessage(
		conn,
		&incomingAck,
	); err != nil {
		return nil, "", err
	}

	if incomingAck.Type != "HELLO_ACK" {
		return nil, "", fmt.Errorf(
			"expected HELLO_ACK, got %q",
			incomingAck.Type,
		)
	}

	var peerAck HelloAck

	if err := json.Unmarshal(
		incomingAck.Data,
		&peerAck,
	); err != nil {
		return nil, "", err
	}

	if peerAck.Version != protocol {
		return nil, "", fmt.Errorf(
			"unsupported peer ACK protocol version %d, expected %d",
			peerAck.Version,
			protocol,
		)
	}

	if peerAck.Namespace != peerHello.Namespace {
		return nil, "", fmt.Errorf(
			"peer namespace changed during handshake",
		)
	}

	if peerAck.PublicKey != peerHello.PublicKey {
		return nil, "", fmt.Errorf(
			"peer identity changed during handshake",
		)
	}

	if peerAck.Nonce != peerHello.Nonce {
		return nil, "", fmt.Errorf(
			"peer nonce changed during handshake",
		)
	}

	peerSignature, err := hex.DecodeString(
		peerAck.Signature,
	)
	if err != nil ||
		len(peerSignature) != ed25519.SignatureSize {
		return nil, "", fmt.Errorf(
			"invalid peer signature",
		)
	}

	if !verifyHandshake(
		peerHello.Namespace,
		local.Namespace,
		peerPublic,
		local.PublicKey,
		peerNonce,
		localNonce,
		peerSignature,
	) {
		return nil, "", fmt.Errorf(
			"invalid peer handshake signature",
		)
	}

	return peerPublic, peerHello.Namespace, nil
}

func authenticateConnection(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) (*Session, error) {
	_ = conn.SetDeadline(
		time.Now().Add(connectionTimeout),
	)

	peerPublic, peerNamespace, err := performHandshake(
		conn,
		local,
	)
	if err != nil {
		return nil, err
	}

	if err := db.RecordPeerIdentity(
		peerNamespace,
		peerPublic,
	); err != nil {
		return nil, fmt.Errorf(
			"record peer identity: %w",
			err,
		)
	}

	_ = conn.SetDeadline(
		time.Time{},
	)

	return &Session{
		Conn:          conn,
		Peer:          ed25519.PublicKey(peerPublic),
		PeerNamespace: peerNamespace,
	}, nil
}

func HandleConnection(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) error {
	defer conn.Close()

	session, err := authenticateConnection(
		conn,
		local,
		db,
	)
	if err != nil {
		return err
	}

	fmt.Printf(
		"authenticated peer %s::%s\n",
		session.PeerNamespace,
		identity.Fingerprint(session.Peer),
	)

	return sessionLoop(
		session,
		local,
		db,
	)
}

func sessionLoop(
	session *Session,
	local *identity.Identity,
	db *database.Database,
) error {
	for {
		var msg Message

		if err := receiveMessage(
			session.Conn,
			&msg,
		); err != nil {
			if err == io.EOF {
				return nil
			}

			return fmt.Errorf(
				"receive from peer: %w",
				err,
			)
		}

		switch msg.Type {
		case messageTypeSend:
			if err := handleIncomingMessage(
				session,
				local,
				db,
				msg.Data,
			); err != nil {
				return fmt.Errorf(
					"handle incoming message: %w",
					err,
				)
			}

		default:
			return fmt.Errorf(
				"unsupported message type %q",
				msg.Type,
			)
		}
	}
}

func Dial(
	address string,
	local *identity.Identity,
	db *database.Database,
) (*Session, error) {
	conn, err := net.DialTimeout(
		"tcp",
		address,
		connectionTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"connect to peer: %w",
			err,
		)
	}

	session, err := authenticateConnection(
		conn,
		local,
		db,
	)
	if err != nil {
		conn.Close()

		return nil, fmt.Errorf(
			"handshake failed: %w",
			err,
		)
	}

	fmt.Printf(
		"authenticated peer %s::%s\n",
		session.PeerNamespace,
		identity.Fingerprint(session.Peer),
	)

	return session, nil
}

func DialPersistent(
	address string,
	local *identity.Identity,
	db *database.Database,
) {
	for {
		session, err := Dial(
			address,
			local,
			db,
		)

		if err != nil {
			fmt.Printf(
				"connection attempt failed: %v\n",
				err,
			)
		} else {
			err := sessionLoop(
				session,
				local,
				db,
			)

			session.Conn.Close()

			if err != nil {
				fmt.Printf(
					"persistent session closed: %v\n",
					err,
				)
			} else {
				fmt.Println(
					"connection closed",
				)
			}
		}

		time.Sleep(5 * time.Second)
	}
}
