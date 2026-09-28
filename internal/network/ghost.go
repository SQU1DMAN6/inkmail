package network

import (
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
	NextMailboxID string                  `json:"next_mailbox_id,omitempty"`
	HopsLeft      int                     `json:"hops_left"`
	Envelope      message.MailboxEnvelope `json:"envelope"`
}

// maxGhostHops bounds forwarding loops across cooperating Daddies.
const maxGhostHops = 5

// handleRelayProbe answers a latency probe with the echoed nonce.
func handleRelayProbe(
	session *Session,
	raw json.RawMessage,
) error {
	var probe relayProbeBody

	if err := json.Unmarshal(raw, &probe); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeRelayProbeAck,
			Data: marshalJSON(relayProbeBody{Nonce: "", SentAt: time.Now().Unix()}),
		})
	}

	return sendMessage(session, Message{
		Type: messageTypeRelayProbeAck,
		Data: marshalJSON(relayProbeBody{
			Nonce:     probe.Nonce,
			SentAt:    probe.SentAt,
			Responder: "",
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

	session, err := DialAnonymous(relay, db)
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

// handleGhostForward advances an opaque mailbox envelope without identity data.
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

	if err := body.Envelope.Validate(); err != nil {
		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{
				MessageID: body.Envelope.ID,
				Status:    statusRejected,
				Reason:    err.Error(),
			}),
		})
	}
	if len(session.Peer) != 32 || session.PeerAnonymous {
		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{MessageID: body.Envelope.ID, Status: statusRejected, Reason: "authenticated relay identity required"}),
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

	localMailboxID, err := db.GetOrCreateMailboxID()
	if err != nil {
		return err
	}
	if body.Envelope.MailboxID == localMailboxID {
		status := statusDelivered
		reason := ""
		if err := receiveMailboxEnvelope(db, local, body.Envelope); err != nil {
			status = statusRejected
			reason = err.Error()
		}

		return sendMessage(session, Message{
			Type: messageTypeGhostForwardAck,
			Data: marshalJSON(ackBody{
				MessageID: body.Envelope.ID,
				Status:    status,
				Reason:    reason,
			}),
		})
	}

	if err := forwardGhostEnvelope(local, db, session.Peer, body); err != nil {
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

func forwardGhostEnvelope(
	local *identity.Identity,
	db *database.Database,
	submitterKey []byte,
	body ghostForwardBody,
) error {
	if route, err := db.GetMailboxRoute(body.Envelope.MailboxID); err == nil {
		next := ghostForwardBody{
			NextMailboxID: body.Envelope.MailboxID,
			HopsLeft:      body.HopsLeft - 1,
			Envelope:      body.Envelope,
		}

		if err := sendGhostForward(route, local, db, next); err == nil {
			return nil
		}
		_ = db.DeleteExpiredMailboxRoutes()
	}

	for _, sibling := range DaddyAddresses(db, DefaultRelaysPath()) {
		if strings.TrimSpace(sibling) == "" {
			continue
		}

		next := ghostForwardBody{
			NextMailboxID: body.NextMailboxID,
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

	_, err = db.StoreOpaqueHeldMessageForUser(body.Envelope.ID, body.Envelope.MailboxID,
		payload, time.Now().Add(time.Duration(HeldMessageTTL)*time.Second).Unix(), submitterKey)
	return err
}

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
