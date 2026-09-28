package network

// frame.go implements the InkMail frame layer for the temporary ghost
// connections used by every protocol exchange.
//
// Every frame is length-prefixed and size limited (SPEC section 49). Once the
// handshake has installed session keys the frame payload is additionally
// sealed with the directional ChaCha20-Poly1305 transport key, so the JSON
// bodies below are never visible on the wire (SPEC section 31).

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"golang.org/x/crypto/chacha20poly1305"
)

// maxUint64 guards the transport nonce counter against wrap-around.
const maxUint64 = ^uint64(0)

func writeFrame(
	conn net.Conn,
	payload []byte,
) error {
	if len(payload) > maxFrameSize {
		return fmt.Errorf(
			"frame too large",
		)
	}

	if err := writeAll(conn, []byte(magic)); err != nil {
		return err
	}

	var header [8]byte

	binary.BigEndian.PutUint32(
		header[:4],
		uint32(len(payload)),
	)

	if err := writeAll(conn, header[:4]); err != nil {
		return err
	}

	return writeAll(conn, payload)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func readFrame(
	conn net.Conn,
) ([]byte, error) {
	return readFrameLimit(conn, maxFrameSize)
}

func readFrameLimit(conn net.Conn, limit uint32) ([]byte, error) {
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

	if length > maxFrameSize || length > limit {
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

// transportNonce builds the deterministic nonce for a directional counter.
// The counter is placed in the upper four bytes so the nonce never repeats
// for the lifetime of a session key.
func transportNonce(counter uint64) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)

	binary.BigEndian.PutUint64(
		nonce[chacha20poly1305.NonceSize-8:],
		counter,
	)

	return nonce
}

func writeEncryptedFrame(
	session *Session,
	payload []byte,
) error {
	if !session.Encrypted() {
		return writeFrame(session.Conn, payload)
	}

	if session.sendCounter == maxUint64 {
		return fmt.Errorf(
			"transport nonce exhausted",
		)
	}

	nonce := transportNonce(session.sendCounter)
	session.sendCounter++

	sealed := session.sendAead.Seal(
		nil,
		nonce,
		payload,
		nil,
	)

	// The sealed blob carries its own length so the receiver can validate
	// it before attempting to open it.
	frame := make([]byte, 4+len(sealed))

	binary.BigEndian.PutUint32(
		frame[:4],
		uint32(len(sealed)),
	)

	copy(frame[4:], sealed)

	return writeFrame(session.Conn, frame)
}

func readEncryptedFrame(
	session *Session,
) ([]byte, error) {
	if !session.Encrypted() {
		return readFrame(session.Conn)
	}

	frame, err := readFrame(session.Conn)
	if err != nil {
		return nil, err
	}

	if len(frame) < 4 {
		return nil, fmt.Errorf(
			"encrypted frame truncated",
		)
	}

	sealedLength := binary.BigEndian.Uint32(
		frame[:4],
	)

	if int(sealedLength) != len(frame)-4 {
		return nil, fmt.Errorf(
			"encrypted frame has invalid length",
		)
	}

	if session.recvCounter == maxUint64 {
		return nil, fmt.Errorf(
			"transport nonce exhausted",
		)
	}

	nonce := transportNonce(session.recvCounter)
	session.recvCounter++

	opened, err := session.recvAead.Open(
		nil,
		nonce,
		frame[4:],
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decrypt transport frame: %w",
			err,
		)
	}

	return opened, nil
}

func sendMessage(
	session *Session,
	msg Message,
) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf(
			"marshal protocol message: %w",
			err,
		)
	}

	if len(data) > maxFrameSize {
		return fmt.Errorf(
			"protocol message too large",
		)
	}

	return writeEncryptedFrame(session, data)
}

func receiveMessage(
	session *Session,
	msg *Message,
) error {
	data, err := readEncryptedFrame(session)
	if err != nil {
		return err
	}

	if err := json.Unmarshal(data, msg); err != nil {
		return fmt.Errorf(
			"unmarshal protocol message: %w",
			err,
		)
	}

	if msg.Type == "" {
		return fmt.Errorf(
			"protocol message has no type",
		)
	}

	return nil
}
