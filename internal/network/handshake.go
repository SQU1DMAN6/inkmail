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
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
}

type HelloAck struct {
	Version   int    `json:"version"`
	PublicKey string `json:"public_key"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

type Session struct {
	Conn    net.Conn
	Peer    []byte
	Address string
}

func writeFrame(
	conn net.Conn,
	payload []byte,
) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf("frame too large")
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
		Version: protocol,
		PublicKey: hex.EncodeToString(
			local.PublicKey,
		),
		Nonce: hex.EncodeToString(nonce),
	}

	return hello, nonce, nil
}

func signHandshake(
	local *identity.Identity,
	peerPublic []byte,
	peerNonce []byte,
	localNonce []byte,
) []byte {
	data := append(
		[]byte(handshakeTag),
		peerNonce...,
	)

	data = append(
		data,
		localNonce...,
	)

	data = append(
		data,
		peerPublic...,
	)

	data = append(
		data,
		local.PublicKey...,
	)

	return ed25519.Sign(
		local.PrivateKey,
		data,
	)
}

func verifyHandshake(
	peerPublic []byte,
	localPublic []byte,
	peerNonce []byte,
	localNonce []byte,
	signature []byte,
) bool {
	data := append(
		[]byte(handshakeTag),
		localNonce...,
	)

	data = append(
		data,
		peerNonce...,
	)

	data = append(
		data,
		localPublic...,
	)

	data = append(
		data,
		peerPublic...,
	)

	return ed25519.Verify(
		ed25519.PublicKey(peerPublic),
		data,
		signature,
	)
}

func makeAck(
	local *identity.Identity,
	peerPublic []byte,
	peerNonce []byte,
	localNonce []byte,
) HelloAck {
	signature := signHandshake(
		local,
		peerPublic,
		peerNonce,
		localNonce,
	)

	return HelloAck{
		Version: protocol,
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
) ([]byte, error) {
	localHello, localNonce, err := createHello(local)
	if err != nil {
		return nil, err
	}

	helloData, err := json.Marshal(
		localHello,
	)
	if err != nil {
		return nil, err
	}

	if err := sendMessage(
		conn,
		Message{
			Type: "HELLO",
			Data: helloData,
		},
	); err != nil {
		return nil, err
	}

	var incoming Message

	if err := receiveMessage(
		conn,
		&incoming,
	); err != nil {
		return nil, err
	}

	if incoming.Type != "HELLO" {
		return nil, fmt.Errorf(
			"expected HELLO, got %q",
			incoming.Type,
		)
	}

	var peerHello Hello

	if err := json.Unmarshal(
		incoming.Data,
		&peerHello,
	); err != nil {
		return nil, err
	}

	if peerHello.Version != protocol {
		return nil, fmt.Errorf(
			"unsupported protocol version %d",
			peerHello.Version,
		)
	}

	peerPublic, err := hex.DecodeString(
		peerHello.PublicKey,
	)
	if err != nil ||
		len(peerPublic) != ed25519.PublicKeySize {
		return nil, fmt.Errorf(
			"invalid peer public key",
		)
	}

	peerNonce, err := hex.DecodeString(
		peerHello.Nonce,
	)
	if err != nil || len(peerNonce) != 32 {
		return nil, fmt.Errorf(
			"invalid peer nonce",
		)
	}

	ack := makeAck(
		local,
		peerPublic,
		peerNonce,
		localNonce,
	)

	ackData, err := json.Marshal(ack)
	if err != nil {
		return nil, err
	}

	if err := sendMessage(
		conn,
		Message{
			Type: "HELLO_ACK",
			Data: ackData,
		},
	); err != nil {
		return nil, err
	}

	var incomingAck Message

	if err := receiveMessage(
		conn,
		&incomingAck,
	); err != nil {
		return nil, err
	}

	if incomingAck.Type != "HELLO_ACK" {
		return nil, fmt.Errorf(
			"expected HELLO_ACK, got %q",
			incomingAck.Type,
		)
	}

	var peerAck HelloAck

	if err := json.Unmarshal(
		incomingAck.Data,
		&peerAck,
	); err != nil {
		return nil, err
	}

	if peerAck.Version != protocol {
		return nil, fmt.Errorf(
			"unsupported peer ACK protocol version %d, expected %d",
			peerAck.Version,
			protocol,
		)
	}

	if peerAck.PublicKey != peerHello.PublicKey {
		return nil, fmt.Errorf(
			"peer identity changed during handshake",
		)
	}

	if peerAck.Nonce != peerHello.Nonce {
		return nil, fmt.Errorf(
			"peer nonce changed during handshake",
		)
	}

	peerSignature, err := hex.DecodeString(
		peerAck.Signature,
	)
	if err != nil ||
		len(peerSignature) != ed25519.SignatureSize {
		return nil, fmt.Errorf(
			"invalid peer signature",
		)
	}

	if !verifyHandshake(
		peerPublic,
		local.PublicKey,
		peerNonce,
		localNonce,
		peerSignature,
	) {
		return nil, fmt.Errorf(
			"invalid peer handshake signature",
		)
	}

	return peerPublic, nil
}

func authenticateConnection(
	conn net.Conn,
	local *identity.Identity,
	db *database.Database,
) (*Session, error) {
	_ = conn.SetDeadline(
		time.Now().Add(connectionTimeout),
	)

	peerPublic, err := performHandshake(
		conn,
		local,
	)
	if err != nil {
		return nil, err
	}

	address := conn.RemoteAddr().String()

	if err := db.UpsertPeer(
		peerPublic,
		address,
	); err != nil {
		return nil, fmt.Errorf(
			"store peer: %w",
			err,
		)
	}

	_ = conn.SetDeadline(
		time.Time{},
	)

	return &Session{
		Conn:    conn,
		Peer:    peerPublic,
		Address: address,
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
		"authenticated peer %s from %s\n",
		identity.Fingerprint(session.Peer),
		session.Address,
	)

	return sessionLoop(session)
}

func sessionLoop(
	session *Session,
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
) error {
	conn, err := net.DialTimeout(
		"tcp",
		address,
		connectionTimeout,
	)
	if err != nil {
		return fmt.Errorf(
			"connect to %s: %w",
			address,
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

		return fmt.Errorf(
			"handshake with %s: %w",
			address,
			err,
		)
	}

	fmt.Printf(
		"authenticated peer %s at %s\n",
		identity.Fingerprint(session.Peer),
		address,
	)

	return sessionLoop(session)
}

func DialPersistent(
	address string,
	local *identity.Identity,
	db *database.Database,
) {
	for {
		err := Dial(
			address,
			local,
			db,
		)

		if err != nil {
			fmt.Printf(
				"connection to %s failed: %v\n",
				address,
				err,
			)
		} else {
			fmt.Printf(
				"connection to %s closed\n",
				address,
			)
		}

		time.Sleep(5 * time.Second)
	}
}
