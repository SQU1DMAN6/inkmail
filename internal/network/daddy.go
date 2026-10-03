package network

// daddy.go implements Daddy: an optional transportation node that
// provides route registration, route lookup, temporary relay and other messaging stuff
//
// Daddy never possesses a peer's private keys, so it can never read a
// message subject or body. It only ever sees the encrypted envelope plus the
// routing metadata required to deliver it (SPEC sections 43 and 44).

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

// metaDaddyAddress is the node_meta key holding the configured Daddy node.
const metaDaddyAddress = "daddy_address"

// metaAdvertisedAddress is the node_meta key holding the endpoint this node
// publishes to Daddy. When empty it is discovered automatically.
const metaAdvertisedAddress = "advertised_address"

// maxRouteLifetime caps how far into the future a route may be advertised.
// A node cannot permanently reserve an address (SPEC section 9).
const maxRouteLifetime = 24 * time.Hour

// maxSessionRequests bounds how many protocol exchanges one ghost connection
// may carry. FETCH_MESSAGES is followed by one DELIVERY_ACK per message.
const maxSessionRequests = maxHeldMessageBatch + 16

// routeRegistration is the body of REGISTER_ROUTE.
type routeRegistration struct {
	MailboxID string `json:"mailbox_id"`
	Address   string `json:"address"`
	ExpiresAt int64  `json:"expires_at"`
}

// routeRegistrationAck is the body of REGISTER_ROUTE_ACK.
type routeRegistrationAck struct {
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// routeLookup is the body of LOOKUP_ROUTE.
type routeLookup struct {
	MailboxID string `json:"mailbox_id"`
}

// routeLookupResult is the body of LOOKUP_ROUTE_ACK.
type routeLookupResult struct {
	Found     bool   `json:"found"`
	Status    string `json:"status,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Address   string `json:"address,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// fetchRequest is the body of FETCH_MESSAGES.
type fetchRequest struct {
	MailboxID string `json:"mailbox_id"`
}

// deliveryBody is the body of MESSAGE_DELIVERY. It carries encrypted
// envelopes only; Daddy cannot decrypt any of them.
type deliveryBody struct {
	Messages []message.MailboxEnvelope `json:"messages"`
}

// RemoteRoute is a route learned from Daddy or from a direct connection.
type RemoteRoute struct {
	Address   string
	ExpiresAt int64
}

func validateAdvertisedAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf(
			"invalid route address %q: %w",
			address,
			err,
		)
	}

	if host == "" || port == "" {
		return fmt.Errorf(
			"invalid route address %q",
			address,
		)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Daddy: server side
//
// These handlers run on whichever node receives a protocol request. A node
// that is configured as Daddy simply answers route and hold-and-forward
// requests; the same code path is harmless on an ordinary node because it is
// only reached when a peer actually asks for it.
// ---------------------------------------------------------------------------

// replyRegistration answers a REGISTER_ROUTE request.
func replyRegistration(
	session *Session,
	status string,
	reason string,
	expiresAt int64,
) error {
	return sendMessage(session, Message{
		Type: messageTypeRegisterRouteAck,
		Data: marshalJSON(routeRegistrationAck{
			Status:    status,
			Reason:    reason,
			ExpiresAt: expiresAt,
		}),
	})
}

func authorizeMailboxOwner(session *Session, db *database.Database, mailboxID string) error {
	if err := session.authorizeMailboxID(mailboxID); err != nil {
		return err
	}
	if len(session.Peer) != 32 || session.PeerAnonymous {
		return errors.New("stable authenticated mailbox owner required")
	}
	owned, err := db.MailboxOwnedBy(mailboxID, session.Peer)
	if err != nil {
		return err
	}
	if !owned {
		return errors.New("session identity does not own mailbox")
	}
	return nil
}

// handleRegisterRoute authenticates the caller and stores a temporary route
// (SPEC section 8). The identity is taken from the completed handshake, never
// from the request body, so a client cannot advertise an identity it does not
// own.
func handleRegisterRoute(
	session *Session,
	db *database.Database,
	data []byte,
) error {
	var registration routeRegistration

	if err := json.Unmarshal(data, &registration); err != nil {
		return replyRegistration(
			session,
			statusRejected,
			"malformed registration",
			0,
		)
	}

	if err := message.ValidateMailboxID(registration.MailboxID); err != nil {
		return replyRegistration(session, statusRejected, err.Error(), 0)
	}
	if err := session.authorizeMailboxID(registration.MailboxID); err != nil {
		return replyRegistration(session, statusRejected, err.Error(), 0)
	}
	if len(session.Peer) != 32 || session.PeerNamespace == "relay" {
		return replyRegistration(session, statusRejected, "authenticated mailbox owner required", 0)
	}

	if err := validateAdvertisedAddress(registration.Address); err != nil {
		return replyRegistration(
			session,
			statusRejected,
			err.Error(),
			0,
		)
	}

	now := time.Now().Unix()

	// A route can never be reserved indefinitely (SPEC section 9).
	if limit := time.Now().Add(maxRouteLifetime).Unix(); registration.ExpiresAt > limit {
		registration.ExpiresAt = limit
	}

	if registration.ExpiresAt <= now {
		return replyRegistration(
			session,
			statusRejected,
			"route is already expired",
			0,
		)
	}

	if err := db.SetOwnedMailboxRoute(
		registration.MailboxID,
		registration.Address,
		registration.ExpiresAt,
		session.Peer,
	); err != nil {
		return replyRegistration(
			session,
			statusRejected,
			safeRouteRegistrationReason(err),
			0,
		)
	}

	return replyRegistration(
		session,
		statusOK,
		"",
		registration.ExpiresAt,
	)
}

// replyLookup answers a LOOKUP_ROUTE request.
func replyLookup(
	session *Session,
	result routeLookupResult,
) error {
	return sendMessage(session, Message{
		Type: messageTypeLookupRouteAck,
		Data: marshalJSON(result),
	})
}

// handleLookupRoute resolves an opaque mailbox ID to its temporary route.
func handleLookupRoute(
	session *Session,
	db *database.Database,
	data []byte,
) error {
	var lookup routeLookup

	if err := json.Unmarshal(data, &lookup); err != nil {
		return replyLookup(session, routeLookupResult{
			Status: statusRejected,
			Reason: "malformed lookup",
		})
	}

	if err := message.ValidateMailboxID(lookup.MailboxID); err != nil {
		return replyLookup(session, routeLookupResult{
			Status: statusRejected,
			Reason: "invalid mailbox identifier",
		})
	}

	result := routeLookupResult{
		Status: statusOK,
	}

	address, expiresAt, err := db.GetMailboxRouteWithExpiry(lookup.MailboxID)
	if err != nil {
		result.Status = "unreachable"
		result.Reason = "no active route"

		return replyLookup(session, result)
	}

	result.Found = true
	result.Address = address
	result.ExpiresAt = expiresAt

	return replyLookup(session, result)
}

// replyHold answers a HOLD_MESSAGE request.
func replyHold(
	session *Session,
	messageID string,
	status string,
	reason string,
) error {
	return sendAck(
		session,
		messageTypeHoldAck,
		messageID,
		status,
		reason,
	)
}

// handleHoldMessage accepts an encrypted envelope for hold-and-forward
// delivery (SPEC sections 21 to 26).
//
// Daddy stores opaque ciphertext; recipients perform the envelope's
// cryptographic authentication after decryption.
func handleHoldMessage(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	data []byte,
) error {
	var envelope message.MailboxEnvelope
	accepted := false
	defer func() {
		if accepted {
			runtimeStats.acceptedMessages.Add(1)
		} else {
			runtimeStats.rejectedMessages.Add(1)
			runtimeStats.rejectedBytes.Add(uint64(len(data)))
		}
	}()

	if len(data) > database.MaxOpaqueEnvelopeSize {
		return replyHold(session, "", statusRejected, "held envelope exceeds size limit")
	}
	if len(session.Peer) != 32 || session.PeerAnonymous {
		return replyHold(session, "", statusRejected, "authenticated sender required")
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return replyHold(session, "", statusRejected, "malformed envelope")
	}

	if err := envelope.Validate(); err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	expiresAt := time.Now().Add(HeldMessageTTL * time.Second).Unix()
	stored, err := db.StoreOpaqueHeldMessageForUser(envelope.ID, envelope.MailboxID, payload, expiresAt, session.Peer)
	if err != nil {
		reason := "storage admission failed"
		if strings.Contains(err.Error(), "quota exceeded") {
			reason = "relay storage quota exceeded"
		}
		return replyHold(session, envelope.ID, statusRejected, reason)
	}
	if !stored {
		runtimeStats.replayRejections.Add(1)
		return replyHold(session, envelope.ID, statusAlreadyStored, "")
	}
	accepted = true
	runtimeStats.acceptedBytes.Add(uint64(len(payload)))

	// HOLD_ACK means "accepted", not "delivered" (SPEC section 24).
	if err := replyHold(session, envelope.ID, statusHeld, ""); err != nil {
		return err
	}

	// If the mailbox has a live route, try delivery immediately. Failure leaves
	// only the opaque encrypted envelope held for the regular mailbox poll.
	scheduleRelayHeldMessage(local, db, envelope, session.Peer)

	return nil
}

func safeRouteRegistrationReason(err error) string {
	if strings.Contains(err.Error(), "quota exceeded") {
		return "route registration quota exceeded"
	}
	if strings.Contains(err.Error(), "owned by a different authenticated identity") {
		return "mailbox ownership conflict"
	}
	return "route registration failed"
}

func replyDelivery(
	session *Session,
	envelopes []message.MailboxEnvelope,
) error {
	return sendMessage(session, Message{
		Type: messageTypeDelivery,
		Data: marshalJSON(deliveryBody{
			Messages: envelopes,
		}),
	})
}

// handleFetchMessages returns the held envelopes belonging to the
// authenticated caller (SPEC section 23).
func handleFetchMessages(
	session *Session,
	db *database.Database,
	data []byte,
) error {
	var request fetchRequest

	if err := json.Unmarshal(data, &request); err != nil {
		return fmt.Errorf(
			"unmarshal fetch request: %w",
			err,
		)
	}

	if err := message.ValidateMailboxID(request.MailboxID); err != nil {
		return replyDelivery(session, nil)
	}
	if err := authorizeMailboxOwner(session, db, request.MailboxID); err != nil {
		return replyDelivery(session, nil)
	}

	held, err := db.ListOpaqueHeldMessages(request.MailboxID, maxHeldMessageBatch)
	if err != nil {
		return fmt.Errorf(
			"get held messages: %w",
			err,
		)
	}

	envelopes := make(
		[]message.MailboxEnvelope,
		0,
		len(held),
	)

	for _, stored := range held {
		if len(envelopes) >= maxHeldMessageBatch {
			break
		}

		var envelope message.MailboxEnvelope

		if err := json.Unmarshal(
			stored.Payload,
			&envelope,
		); err != nil {
			continue
		}

		if err := envelope.Validate(); err == nil && strings.EqualFold(envelope.MailboxID, request.MailboxID) {
			envelopes = append(envelopes, envelope)
			session.recordFetchedMessage(envelope.ID, request.MailboxID)
		}
	}

	return replyDelivery(session, envelopes)
}

// handleDeliveryAck processes a DELIVERY_ACK (SPEC sections 23 to 25).
//
// A delivered message is deleted immediately. A rejected message is kept and
// retried until its expiry is reached.
func handleDeliveryAck(
	session *Session,
	db *database.Database,
	data []byte,
) error {
	var ack ackBody

	if err := json.Unmarshal(data, &ack); err != nil {
		return fmt.Errorf(
			"unmarshal delivery acknowledgement: %w",
			err,
		)
	}

	if ack.MessageID == "" {
		return errors.New(
			"delivery acknowledgement has no message ID",
		)
	}
	if err := authorizeMailboxOwner(session, db, ack.MailboxID); err != nil {
		return fmt.Errorf("unauthorized delivery acknowledgement: %w", err)
	}
	if ack.Status != statusDelivered && ack.Status != statusRejected {
		return fmt.Errorf("unknown delivery status %q", ack.Status)
	}
	if !session.consumeFetchedMessage(ack.MessageID, ack.MailboxID) {
		return errors.New("delivery acknowledgement does not match an envelope offered in this session")
	}

	switch ack.Status {
	case statusDelivered:
		if err := db.DeleteOpaqueHeldMessage(ack.MessageID, ack.MailboxID); err != nil {
			return fmt.Errorf("delete delivered opaque message: %w", err)
		}

	case statusRejected:
		// Keep the envelope. Daddy will retry until expires_at.

	}

	return sendMessage(session, Message{
		Type: messageTypeDeleteAck,
		Data: marshalJSON(ackBody{MessageID: ack.MessageID, MailboxID: ack.MailboxID, Status: statusOK}),
	})
}

var relayForwardState = struct {
	sync.Mutex
	active map[[32]byte]int
}{active: make(map[[32]byte]int)}

func scheduleRelayHeldMessage(local *identity.Identity, db *database.Database, envelope message.MailboxEnvelope, userKey []byte) {
	userHash := sha256.Sum256(userKey)
	relayForwardState.Lock()
	if relayForwardState.active[userHash] >= 4 {
		relayForwardState.Unlock()
		return
	}
	relayForwardState.active[userHash]++
	relayForwardState.Unlock()
	go func() {
		defer func() {
			relayForwardState.Lock()
			relayForwardState.active[userHash]--
			if relayForwardState.active[userHash] == 0 {
				delete(relayForwardState.active, userHash)
			}
			relayForwardState.Unlock()
		}()
		relayHeldMessage(local, db, envelope)
	}()
}

// ---------------------------------------------------------------------------
// Daddy: client side
//
// These helpers drive the ghost send flow (SPEC section 11) and the daemon's
// route registration loop (SPEC sections 8 and 9).
// ---------------------------------------------------------------------------

// daddyAddressFromDB returns the configured Daddy node, or "" when Daddy is
// disabled. An empty result is not an error: direct peer communication must
// continue to work without Daddy (SPEC section 7).
func daddyAddressFromDB(db *database.Database) string {
	if db == nil {
		return ""
	}

	address, err := db.GetMeta(metaDaddyAddress)
	if err != nil {
		return ""
	}

	return strings.TrimSpace(address)
}

// SetDaddyAddress records the fallback node used for route lookup, relay and
// hold-and-forward.
func SetDaddyAddress(
	db *database.Database,
	address string,
) error {
	return db.SetMeta(
		metaDaddyAddress,
		strings.TrimSpace(address),
	)
}

// SetAdvertisedAddress records the endpoint this node publishes to Daddy. An
// empty value restores automatic discovery.
func SetAdvertisedAddress(
	db *database.Database,
	address string,
) error {
	address = strings.TrimSpace(address)

	if address == "" {
		return db.SetMeta(metaAdvertisedAddress, "")
	}

	if err := validateAdvertisedAddress(address); err != nil {
		return err
	}

	return db.SetMeta(metaAdvertisedAddress, address)
}

// discoverLocalHost returns the local address used to reach remote.
//
// A DNS lookup is not involved: connecting a UDP socket only asks the routing
// table which local interface would be used.
func discoverLocalHost(remote string) (string, error) {
	conn, err := net.Dial("udp", remote)
	if err != nil {
		return "", fmt.Errorf(
			"discover local address: %w",
			err,
		)
	}

	defer conn.Close()

	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && addr.IP != nil {
		return addr.IP.String(), nil
	}

	return "", errors.New(
		"could not determine local address",
	)
}

// discoverAdvertisedAddress determines the host:port this node should publish.
func discoverAdvertisedAddress(
	db *database.Database,
	remote string,
) (string, error) {
	if value, err := db.GetMeta(metaAdvertisedAddress); err == nil {
		if value = strings.TrimSpace(value); value != "" {
			if err := validateAdvertisedAddress(value); err == nil {
				return value, nil
			}
		}
	}

	portValue, err := db.GetMeta("listen_port")
	if err != nil {
		return "", errors.New(
			"listening port is not known; start inkmaild before registering a route",
		)
	}

	port := strings.TrimSpace(portValue)
	if port == "" {
		return "", errors.New("listening port is not known")
	}

	host, err := discoverLocalHost(remote)
	if err != nil {
		return "", err
	}

	return net.JoinHostPort(host, port), nil
}

// RegisterRouteWithDaddy advertises this node's temporary route and closes the
// connection immediately (SPEC sections 3 and 8).
func RegisterRouteWithDaddy(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) error {
	address, err := discoverAdvertisedAddress(db, daddyAddress)
	if err != nil {
		return err
	}

	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return fmt.Errorf("connect to Daddy: %w", err)
	}

	defer session.Close()

	mailboxID, err := db.GetOrCreateMailboxID()
	if err != nil {
		return err
	}
	if err := session.authorizeMailboxID(mailboxID); err != nil {
		return fmt.Errorf("authorize mailbox route registration: %w", err)
	}
	registration := routeRegistration{
		MailboxID: mailboxID,
		Address:   address,
		ExpiresAt: time.Now().Add(DefaultRouteTTL).Unix(),
	}

	if err := sendMessage(session, Message{
		Type: messageTypeRegisterRoute,
		Data: marshalJSON(registration),
	}); err != nil {
		return fmt.Errorf("send route registration: %w", err)
	}

	var response Message

	if err := receiveMessage(session, &response); err != nil {
		return fmt.Errorf("read route registration ack: %w", err)
	}

	if response.Type != messageTypeRegisterRouteAck {
		return fmt.Errorf(
			"unexpected route registration response %q",
			response.Type,
		)
	}

	var ack routeRegistrationAck

	if err := json.Unmarshal(response.Data, &ack); err != nil {
		return fmt.Errorf("unmarshal route registration ack: %w", err)
	}

	if ack.Status != statusOK {
		return fmt.Errorf("Daddy rejected route: %s", ack.Reason)
	}

	// Remember our own route locally as well, superseding any stale address
	// this node previously advertised (SPEC v0.5 Test I).
	if err := db.RegisterOrReplaceRoute(
		local.Namespace,
		[]byte(local.PublicKey),
		address,
		ack.ExpiresAt,
	); err != nil {
		return err
	}

	return nil
}

// LookupRouteWithDaddy asks Daddy to resolve an identity to a temporary route
// (SPEC section 6.2). The lookup is identity based; the caller never supplies
// an address.
func LookupRouteWithDaddy(
	daddyAddress string,
	db *database.Database,
	mailboxID string,
) (*RemoteRoute, error) {
	if err := message.ValidateMailboxID(mailboxID); err != nil {
		return nil, err
	}

	session, err := DialAnonymous(daddyAddress, db)
	if err != nil {
		return nil, fmt.Errorf("connect to Daddy: %w", err)
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeLookupRoute,
		Data: marshalJSON(routeLookup{
			MailboxID: mailboxID,
		}),
	}); err != nil {
		return nil, fmt.Errorf("send route lookup: %w", err)
	}

	var response Message

	if err := receiveMessage(session, &response); err != nil {
		return nil, fmt.Errorf("read route lookup ack: %w", err)
	}

	if response.Type != messageTypeLookupRouteAck {
		return nil, fmt.Errorf(
			"unexpected route lookup response %q",
			response.Type,
		)
	}

	var result routeLookupResult

	if err := json.Unmarshal(response.Data, &result); err != nil {
		return nil, fmt.Errorf("unmarshal route lookup ack: %w", err)
	}

	if !result.Found {
		return nil, fmt.Errorf(
			"Daddy has no route for mailbox %s: %s",
			mailboxID,
			result.Reason,
		)
	}

	if err := validateAdvertisedAddress(result.Address); err != nil {
		return nil, err
	}

	if result.ExpiresAt <= time.Now().Unix() {
		return nil, fmt.Errorf("Daddy returned an expired route")
	}
	route := &RemoteRoute{Address: result.Address, ExpiresAt: result.ExpiresAt}
	_ = db.SetMailboxRoute(mailboxID, route.Address, route.ExpiresAt)

	return route, nil
}

// SendHoldMessage hands an encrypted envelope to Daddy for safe keeping
// (SPEC section 11). The reply is a HOLD_ACK, which only means "accepted".
func SendHoldMessage(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
	envelope *message.MailboxEnvelope,
) error {
	if envelope == nil {
		return errors.New("no envelope to hold")
	}

	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return fmt.Errorf("connect to Daddy: %w", err)
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeHoldMessage,
		Data: marshalJSON(envelope),
	}); err != nil {
		return fmt.Errorf("send held message: %w", err)
	}

	var response Message

	if err := receiveMessage(session, &response); err != nil {
		return fmt.Errorf("read hold ack: %w", err)
	}

	if response.Type != messageTypeHoldAck {
		return fmt.Errorf(
			"unexpected hold response %q",
			response.Type,
		)
	}

	var ack ackBody

	if err := json.Unmarshal(response.Data, &ack); err != nil {
		return fmt.Errorf("unmarshal hold ack: %w", err)
	}

	if ack.MessageID != envelope.ID {
		return errors.New(
			"hold acknowledgement does not match the message",
		)
	}

	switch ack.Status {
	case statusHeld, statusAlreadyStored:
		return nil
	default:
		return fmt.Errorf(
			"Daddy refused the message: %s",
			ack.Reason,
		)
	}
}

func FetchHeldMessages(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) (int, error) {
	mailboxID, err := db.GetOrCreateMailboxID()
	if err != nil {
		return 0, err
	}

	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return 0, fmt.Errorf("connect to Daddy: %w", err)
	}

	defer session.Close()

	if err := session.authorizeMailboxID(mailboxID); err != nil {
		return 0, err
	}
	if err := sendMessage(session, Message{
		Type: messageTypeFetchMessages,
		Data: marshalJSON(fetchRequest{MailboxID: mailboxID}),
	}); err != nil {
		return 0, fmt.Errorf("send fetch request: %w", err)
	}

	var response Message

	if err := receiveMessage(session, &response); err != nil {
		return 0, fmt.Errorf("read delivery: %w", err)
	}

	if response.Type != messageTypeDelivery {
		return 0, fmt.Errorf(
			"unexpected delivery response %q",
			response.Type,
		)
	}

	var body deliveryBody

	if err := json.Unmarshal(response.Data, &body); err != nil {
		return 0, fmt.Errorf("unmarshal delivery: %w", err)
	}

	delivered := 0

	for _, envelope := range body.Messages {
		status := statusDelivered
		reason := ""
		if err := receiveMailboxEnvelope(db, local, envelope); err != nil {
			status = statusRejected
			reason = err.Error()
		}

		if err := sendMessage(session, Message{
			Type: messageTypeDeliveryAck,
			Data: marshalJSON(ackBody{MessageID: envelope.ID, MailboxID: mailboxID, Status: status, Reason: reason}),
		}); err != nil {
			return delivered, fmt.Errorf(
				"send delivery ack: %w",
				err,
			)
		}
		var ackResponse Message
		if err := receiveMessage(session, &ackResponse); err != nil {
			return delivered, fmt.Errorf("read delivery ack response: %w", err)
		}
		if ackResponse.Type != messageTypeDeleteAck {
			return delivered, fmt.Errorf("unexpected delivery ack response %q", ackResponse.Type)
		}
		var ackResult ackBody
		if err := json.Unmarshal(ackResponse.Data, &ackResult); err != nil {
			return delivered, fmt.Errorf("unmarshal delivery ack response: %w", err)
		}
		if ackResult.MessageID != envelope.ID || ackResult.MailboxID != mailboxID || ackResult.Status != statusOK {
			return delivered, fmt.Errorf("Daddy rejected or mismatched delivery acknowledgement")
		}

		if status == statusDelivered {
			delivered++
		}
	}

	return delivered, nil
}

// deliverEnvelopeToAddress performs one direct ghost delivery: dial,
// authenticate, verify that the peer really is the intended recipient, send
// the encrypted envelope, wait for the acknowledgement and close.
func deliverEnvelopeToAddress(
	local *identity.Identity,
	db *database.Database,
	address string,
	recipientPublicKey []byte,
	envelope message.MailboxEnvelope,
) error {
	session, err := Dial(address, local, db)
	if err != nil {
		return err
	}
	defer session.Close()
	if len(recipientPublicKey) > 0 && !sameBytes([]byte(session.Peer), recipientPublicKey) {
		return fmt.Errorf("peer at %s is not the intended recipient", address)
	}
	if len(recipientPublicKey) == 0 {
		if err := authorizeMailboxOwner(session, db, envelope.MailboxID); err != nil {
			return fmt.Errorf("route endpoint is not the mailbox owner: %w", err)
		}
	}
	if err := sendMessage(session, Message{Type: messageTypeMessage, Data: marshalJSON(envelope)}); err != nil {
		return fmt.Errorf("send opaque mailbox envelope: %w", err)
	}
	var response Message
	if err := receiveMessage(session, &response); err != nil {
		return fmt.Errorf("read message ack: %w", err)
	}
	if response.Type != messageTypeMessageAck {
		return fmt.Errorf("unexpected delivery response %q", response.Type)
	}
	var ack ackBody
	if err := json.Unmarshal(response.Data, &ack); err != nil {
		return fmt.Errorf("unmarshal message ack: %w", err)
	}
	if ack.MessageID != envelope.ID || ack.Status != statusDelivered {
		return fmt.Errorf("recipient did not accept the message: %s", ack.Reason)
	}
	return nil
}

func relayHeldMessage(local *identity.Identity, db *database.Database, envelope message.MailboxEnvelope) {
	address, err := db.GetMailboxRoute(envelope.MailboxID)
	if err != nil {
		return
	}
	if err := deliverEnvelopeToAddress(local, db, address, nil, envelope); err == nil {
		_ = db.DeleteOpaqueHeldMessage(envelope.ID, envelope.MailboxID)
	}
}

func resolveRecipient(db *database.Database, namespace string, publicKey []byte) ([]byte, string, string) {
	var encryptionKey []byte
	var mailboxID string
	if peer, err := db.GetPeerIdentity(namespace, publicKey); err == nil {
		encryptionKey = peer.EncryptionPublicKey
		mailboxID = peer.MailboxID
	}
	address := ""
	if route, err := db.GetRoute(namespace, publicKey); err == nil {
		address = route.Address
	}
	if address == "" && mailboxID != "" {
		address, _ = db.GetMailboxRoute(mailboxID)
	}
	return encryptionKey, address, mailboxID
}

type SendResult struct {
	Delivered bool
	Relayed   bool
	Address   string
}

func ResolveAndSend(
	local *identity.Identity,
	db *database.Database,
	recipientNamespace string,
	recipientPublicKey []byte,
	recipientEncryptionKey []byte,
	recipientMailboxID string,
	msg *message.Message,
) (*SendResult, error) {
	if err := message.ValidateMailboxID(recipientMailboxID); err != nil {
		return nil, fmt.Errorf("recipient contact has no valid mailbox ID: %w", err)
	}
	if len(recipientEncryptionKey) != 32 {
		return nil, fmt.Errorf("recipient contact has no valid encryption key")
	}
	_, directAddress, _ := resolveRecipient(db, recipientNamespace, recipientPublicKey)
	if directAddress == "" {
		for _, daddy := range DaddyAddresses(db, DefaultRelaysPath()) {
			route, err := LookupRouteWithDaddy(daddy, db, recipientMailboxID)
			if err == nil && route != nil {
				directAddress = route.Address
				break
			}
		}
	}
	inner, err := msg.EncryptForRecipient(recipientEncryptionKey, recipientNamespace, local.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt message: %w", err)
	}
	senderMailboxID, err := db.GetOrCreateMailboxID()
	if err != nil {
		return nil, err
	}
	outer, err := message.WrapForMailbox(*inner, recipientMailboxID, senderMailboxID,
		local.EncryptionPublicKey, recipientEncryptionKey)
	if err != nil {
		return nil, err
	}
	if directAddress != "" {
		if err := deliverEnvelopeToAddress(local, db, directAddress, recipientPublicKey, *outer); err == nil {
			return &SendResult{Delivered: true, Address: directAddress}, nil
		}
		_ = db.DeleteRoute(recipientNamespace, recipientPublicKey, directAddress)
	}
	if holdViaRelays(local, db, DaddyAddresses(db, DefaultRelaysPath()), outer) {
		return &SendResult{Relayed: true}, nil
	}
	return nil, errors.New("unable to deliver message: recipient is unreachable and Daddy is unavailable")
}

// StartCleanupRoutine removes expired opaque envelopes and mailbox routes.
func StartCleanupRoutine(db *database.Database) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	ticker := time.NewTicker(DefaultCleanupPeriod)
	go func() {
		defer close(stopped)
		for {
			select {
			case <-ticker.C:
				if expired, err := db.ExpireOpaqueHeldMessages(); err == nil {
					runtimeStats.expiredEnvelopes.Add(uint64(expired))
				}
				_, _ = db.DeleteExpiredMailboxRoutesCount()
				if expired, err := db.DeleteExpiredRoutesCount(); err == nil {
					runtimeStats.expiredPeerRoutes.Add(uint64(expired))
				}
			case <-done:
				ticker.Stop()
				return
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

// DialPersistent periodically registers this opaque mailbox route and fetches
// pending encrypted envelopes from configured Daddies.
//
// Every configured relay is refreshed in turn, so disabling one Daddy does
// not strand the node.
func DialPersistent(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) {
	_ = DialPersistentWithRetry(context.Background(), daddyAddress, local, db, DefaultDaddyRetryInterval)
}

func ValidateDaddyRetryInterval(interval time.Duration) error {
	if interval < MinDaddyRetryInterval || interval > MaxDaddyRetryInterval {
		return fmt.Errorf("Daddy retry interval must be between %s and %s", MinDaddyRetryInterval, MaxDaddyRetryInterval)
	}
	return nil
}

func DialPersistentWithRetry(
	ctx context.Context,
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
	retryInterval time.Duration,
) error {
	if err := ValidateDaddyRetryInterval(retryInterval); err != nil {
		return err
	}
	daddies := DaddyAddresses(db, DefaultRelaysPath())

	if strings.TrimSpace(daddyAddress) != "" {
		seen := false

		for _, existing := range daddies {
			if existing == strings.TrimSpace(daddyAddress) {
				seen = true

				break
			}
		}

		if !seen {
			daddies = append(
				[]string{strings.TrimSpace(daddyAddress)},
				daddies...,
			)
		}
	}

	if len(daddies) == 0 {
		return nil
	}

	for _, daddy := range daddies {
		if err := SetDaddyAddress(db, daddy); err != nil {
			fmt.Printf("Daddy: cannot store address: %v\n", err)
		}
	}

	refresh := func(registerRoutes bool) (bool, bool, bool) {
		connected := true
		retrySoon := false
		routesRegistered := true

		if registerRoutes {
			for _, daddy := range daddies {
				if err := RegisterRouteWithDaddy(
					daddy,
					local,
					db,
				); err != nil {
					fmt.Printf(
						"Daddy %s: route registration failed: %v\n",
						daddy,
						err,
					)
					connected = false
					retrySoon = true
					routesRegistered = false
				}
			}
		}
		if err := SyncOpaqueMailboxOutbox(local, db); err != nil {
			fmt.Printf("Daddy outbox sync failed: %v\n", err)
			connected = false
			retrySoon = true
		}
		retried, err := RetryQueuedMessages(local, db)
		if err != nil {
			fmt.Printf("Queued message retry failed: %v\n", err)
			retrySoon = true
		}
		if retried == 100 {
			retrySoon = true
		}
		if err := collectHeldMessages(local, db); err != nil {
			fmt.Printf("Mailbox fetch failed: %v\n", err)
			connected = false
			retrySoon = true
		}
		return connected, retrySoon, routesRegistered
	}

	knownStatus := false
	lastHealthy := false
	var nextRouteRefresh time.Time
	for {
		registerRoutes := nextRouteRefresh.IsZero() || !time.Now().Before(nextRouteRefresh)
		connected, retrySoon, routesRegistered := refresh(registerRoutes)
		if registerRoutes && routesRegistered {
			nextRouteRefresh = time.Now().Add(DefaultRouteTTL / 2)
		}
		if !knownStatus || connected != lastHealthy {
			if connected {
				fmt.Println("Daddy connected; mailbox service is current.")
			} else {
				fmt.Printf("Daddy unavailable; retrying in %s.\n", retryInterval)
			}
			knownStatus = true
			lastHealthy = connected
		}

		delay := retryInterval
		if untilRouteRefresh := time.Until(nextRouteRefresh); !retrySoon && untilRouteRefresh > 0 && untilRouteRefresh < delay {
			delay = untilRouteRefresh
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil
		case <-timer.C:
		}
	}
}

// collectHeldMessages fetches and acknowledges any envelopes Daddy is holding
// for this identity (SPEC section 23).
//
// Every configured relay is tried in order; one dead Daddy never blocks
// collection from the others (SPEC v0.5 section 19, Test F).
func collectHeldMessages(
	local *identity.Identity,
	db *database.Database,
) error {
	delivered, err := FetchMailboxAll(local, db)
	if err != nil {
		return err
	}

	if delivered > 0 {
		fmt.Printf(
			"Received %d held message(s) from Daddy.\n",
			delivered,
		)
	}

	return nil
}
