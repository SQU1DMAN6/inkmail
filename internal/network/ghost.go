package network

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

// relayProbeBody measures one relay round trip. The responder echoes Nonce.
type relayProbeBody struct {
	Nonce     string `json:"nonce"`
	SentAt    int64  `json:"sent_at"`
	Responder string `json:"responder,omitempty"`
}

// ghostForwardBody wraps one envelope for multi-hop relay. Each layer names
// only the next hop; the inner payload stays opaque to relays.
type ghostForwardBody struct {
	NextNamespace string                   `json:"next_namespace,omitempty"`
	NextPublicKey string                   `json:"next_public_key,omitempty"`
	HopsLeft      int                      `json:"hops_left"`
	Envelope      message.EncryptedMessage `json:"envelope"`
}

// maxGhostHops bounds forwarding loops across cooperating Daddies.
const maxGhostHops = 5

// handleRelayProbe answers a latency probe with the echoed nonce.
func handleRelayProbe(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	raw json.RawMessage,
) error {
	var probe relayProbeBody

	if err := json.Unmarshal(raw, &probe); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeRelayProbeAck,
			Data: marshalJSON(relayProbeBody{Nonce: "", SentAt: time.Now().Unix()}),
		})
	}

	_ = db.RecordPeerIdentityWithKey(
		session.PeerNamespace,
		[]byte(session.Peer),
		session.PeerEncryptionKey,
	)

	return sendMessage(session, Message{
		Type: messageTypeRelayProbeAck,
		Data: marshalJSON(relayProbeBody{
			Nonce:     probe.Nonce,
			SentAt:    probe.SentAt,
			Responder: hex.EncodeToString(local.PublicKey),
		}),
	})
}

// ProbeRelay dials one relay, sends a nonce probe, returns round-trip ms.
func ProbeRelay(
	relay string,
	local *identity.Identity,
	db *database.Database,
) (int64, error) {
	start := time.Now()

	session, err := Dial(relay, local, db)
	if err != nil {
		return 0, err
	}

	defer session.Close()

	nonce := fmt.Sprintf("%d", start.UnixNano())

	if err := sendMessage(session, Message{
		Type: messageTypeRelayProbe,
		Data: marshalJSON(relayProbeBody{Nonce: nonce, SentAt: start.Unix()}),
	}); err != nil {
		return 0, err
	}

	var reply Message

	if err := receiveMessage(session, &reply); err != nil {
		return 0, err
	}

	if reply.Type != messageTypeRelayProbeAck {
		return 0, fmt.Errorf("unexpected probe response %q", reply.Type)
	}

	var ack relayProbeBody

	if err := json.Unmarshal(reply.Data, &ack); err != nil {
		return 0, err
	}

	if ack.Nonce != nonce {
		return 0, fmt.Errorf("probe nonce mismatch")
	}

	return time.Since(start).Milliseconds(), nil
}

// ProbeRelaysAll probes every relay; unreachable relays map to -1.
func ProbeRelaysAll(
	local *identity.Identity,
	db *database.Database,
) map[string]int64 {
	out := map[string]int64{}

	for _, relay := range DaddyAddresses(db, DefaultRelaysPath()) {
		relay = strings.TrimSpace(relay)
		if relay == "" {
			continue
		}

		ms, err := ProbeRelay(relay, local, db)
		if err != nil {
			out[relay] = -1

			continue
		}

		out[relay] = ms
	}

	return out
}

// handleGhostForward receives an onion-style forward: verify the envelope
// signature, deliver locally when addressed here, else advance one hop.
// Relays never decrypt the payload.
func handleGhostForward(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	raw json.RawMessage,
) error {
	var body ghostForwardBody

	if err := json.Unmarshal(raw, &body); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{Status: statusRejected, Reason: "bad forward"}),
		})
	}

	if err := body.Envelope.Verify(); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{
				MessageID: body.Envelope.ID,
				Status:    statusRejected,
				Reason:    err.Error(),
			}),
		})
	}

	if body.HopsLeft < 0 || body.HopsLeft > maxGhostHops {
		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{
				MessageID: body.Envelope.ID,
				Status:    statusRejected,
				Reason:    "hop limit exceeded",
			}),
		})
	}

	localKey := hex.EncodeToString(local.PublicKey)

	if body.Envelope.RecipientNamespace == local.Namespace &&
		strings.EqualFold(body.Envelope.RecipientPublicKey, localKey) {
		status, reason := deliverEnvelopeLocally(db, local, body.Envelope)

		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{
				MessageID: body.Envelope.ID,
				Status:    status,
				Reason:    reason,
			}),
		})
	}

	if err := forwardGhostEnvelope(local, db, body); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{
				MessageID: body.Envelope.ID,
				Status:    statusRejected,
				Reason:    err.Error(),
			}),
		})
	}

	return sendMessage(session, Message{
		Type: messageTypeGhostForwardAck,
		Data: marshalJSON(ackBody{MessageID: body.Envelope.ID, Status: statusOK}),
	})
}

// forwardGhostEnvelope advances one layer: direct route, sibling, else hold.
func forwardGhostEnvelope(
	local *identity.Identity,
	db *database.Database,
	body ghostForwardBody,
) error {
	recipientKey, err := decodeHexField(body.Envelope.RecipientPublicKey)
	if err != nil {
		return err
	}

	if route, err := db.GetRoute(
		body.Envelope.RecipientNamespace,
		recipientKey,
	); err == nil {
		next := ghostForwardBody{
			NextNamespace: body.Envelope.RecipientNamespace,
			NextPublicKey: body.Envelope.RecipientPublicKey,
			HopsLeft:      body.HopsLeft - 1,
			Envelope:      body.Envelope,
		}

		if err := sendGhostForward(route.Address, local, db, next); err == nil {
			return nil
		}

		_ = db.DeleteRoute(body.Envelope.RecipientNamespace, recipientKey, route.Address)
	}

	for _, sibling := range DaddyAddresses(db, DefaultRelaysPath()) {
		if strings.TrimSpace(sibling) == "" {
			continue
		}

		next := ghostForwardBody{
			NextNamespace: body.NextNamespace,
			NextPublicKey: body.NextPublicKey,
			HopsLeft:      body.HopsLeft - 1,
			Envelope:      body.Envelope,
		}

		if err := sendGhostForward(sibling, local, db, next); err == nil {
			return nil
		}
	}

	payload, err := json.Marshal(body.Envelope)
	if err != nil {
		return err
	}

	senderKey, err := decodeHexField(body.Envelope.SenderPublicKey)
	if err != nil {
		return err
	}

	return db.StoreHeldMessage(
		body.Envelope.ID,
		body.Envelope.SenderNamespace,
		senderKey,
		body.Envelope.RecipientNamespace,
		recipientKey,
		payload,
		body.Envelope.CreatedAt,
		time.Now().Add(time.Duration(HeldMessageTTL)*time.Second).Unix(),
	)
}

// sendGhostForward transmits one layer and requires an ack.
func sendGhostForward(
	address string,
	local *identity.Identity,
	db *database.Database,
	body ghostForwardBody,
) error {
	session, err := Dial(address, local, db)
	if err != nil {
		return err
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeGhostForward,
		Data: marshalJSON(body),
	}); err != nil {
		return err
	}

	var reply Message

	if err := receiveMessage(session, &reply); err != nil {
		return err
	}

	if reply.Type != messageTypeGhostForwardAck {
		return fmt.Errorf("unexpected forward response %q", reply.Type)
	}

	var ack ackBody

	if err := json.Unmarshal(reply.Data, &ack); err != nil {
		return err
	}

	if ack.Status != statusOK &&
		ack.Status != statusDelivered &&
		ack.Status != statusHeld {
		if ack.Reason == "" {
			ack.Reason = "forward rejected"
		}

		return fmt.Errorf("forward rejected: %s", ack.Reason)
	}

	return nil
}
