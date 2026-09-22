package network

// daddy.go implements Daddy: an optional, untrusted fallback node that
// provides route registration, route lookup, temporary relay and
// hold-and-forward storage (SPEC sections 7, 8, 21, 23 and 41).
//
// Daddy never possesses a peer's private keys, so it can never read a
// message subject or body. It only ever sees the encrypted envelope plus the
// routing metadata required to deliver it (SPEC sections 43 and 44).

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
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
	Namespace     string `json:"namespace"`
	PublicKey     string `json:"public_key"`
	EncryptionKey string `json:"encryption_key"`
	Address       string `json:"address"`
	ExpiresAt     int64  `json:"expires_at"`
}

// routeRegistrationAck is the body of REGISTER_ROUTE_ACK.
type routeRegistrationAck struct {
	Status    string `json:"status"`
	Reason    string `json:"reason,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

// routeLookup is the body of LOOKUP_ROUTE.
type routeLookup struct {
	Namespace string `json:"namespace"`
	PublicKey string `json:"public_key"`
}

// routeLookupResult is the body of LOOKUP_ROUTE_ACK.
type routeLookupResult struct {
	Found         bool   `json:"found"`
	Status        string `json:"status,omitempty"`
	Reason        string `json:"reason,omitempty"`
	Namespace     string `json:"namespace,omitempty"`
	PublicKey     string `json:"public_key,omitempty"`
	EncryptionKey string `json:"encryption_key,omitempty"`
	Address       string `json:"address,omitempty"`
	ExpiresAt     int64  `json:"expires_at,omitempty"`
}

// fetchRequest is the body of FETCH_MESSAGES.
type fetchRequest struct {
	Namespace string `json:"namespace"`
	PublicKey string `json:"public_key"`
}

// deliveryBody is the body of MESSAGE_DELIVERY. It carries encrypted
// envelopes only; Daddy cannot decrypt any of them.
type deliveryBody struct {
	Messages []message.EncryptedMessage `json:"messages"`
}

// RemoteRoute is a route learned from Daddy or from a direct connection.
type RemoteRoute struct {
	Address       string
	EncryptionKey []byte
	ExpiresAt     int64
}

// verifySessionIdentity refuses to act on a claimed identity unless it is the
// identity that actually completed the handshake (SPEC section 49). Daddy
// must never trust a client merely because the client claims an identity
// (SPEC section 8).
func verifySessionIdentity(
	session *Session,
	namespace string,
	publicKeyHex string,
) error {
	if session.Peer == nil {
		return errors.New(
			"session is not authenticated",
		)
	}

	if namespace != session.PeerNamespace {
		return fmt.Errorf(
			"claimed namespace %q does not match authenticated namespace %q",
			namespace,
			session.PeerNamespace,
		)
	}

	declared, err := hex.DecodeString(publicKeyHex)
	if err != nil {
		return fmt.Errorf(
			"decode claimed public key: %w",
			err,
		)
	}

	if !sameBytes(declared, []byte(session.Peer)) {
		return errors.New(
			"claimed public key does not match authenticated identity",
		)
	}

	return nil
}

// validateAdvertisedAddress checks that an advertised route is a usable
// host:port endpoint.
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

	if err := verifySessionIdentity(
		session,
		registration.Namespace,
		registration.PublicKey,
	); err != nil {
		return replyRegistration(
			session,
			statusRejected,
			err.Error(),
			0,
		)
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

	// The encryption key is the one proven during the handshake; a claimed
	// value in the request body is ignored (SPEC section 49).
	if err := db.RecordPeerIdentityWithKey(
		registration.Namespace,
		[]byte(session.Peer),
		session.PeerEncryptionKey,
	); err != nil {
		return replyRegistration(
			session,
			statusRejected,
			err.Error(),
			0,
		)
	}

	if err := db.RegisterOrReplaceRoute(
		registration.Namespace,
		[]byte(session.Peer),
		registration.Address,
		registration.ExpiresAt,
	); err != nil {
		return replyRegistration(
			session,
			statusRejected,
			err.Error(),
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

// handleLookupRoute resolves an identity to a temporary route (SPEC section 6.2).
//
// The lookup is driven purely by identity. No caller supplies an address.
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

	if err := identity.ValidateNamespace(lookup.Namespace); err != nil {
		return replyLookup(session, routeLookupResult{
			Status: statusRejected,
			Reason: err.Error(),
		})
	}

	publicKey, err := decodeHexField(lookup.PublicKey)
	if err != nil {
		return replyLookup(session, routeLookupResult{
			Status: statusRejected,
			Reason: err.Error(),
		})
	}

	result := routeLookupResult{
		Namespace: lookup.Namespace,
		PublicKey: lookup.PublicKey,
		Status:    statusOK,
	}

	// Publish the recipient's encryption key so the sender can encrypt for
	// the identity even if it has never seen it before.
	if peer, err := db.GetPeerIdentity(
		lookup.Namespace,
		publicKey,
	); err == nil && len(peer.EncryptionPublicKey) > 0 {
		result.EncryptionKey = hex.EncodeToString(
			peer.EncryptionPublicKey,
		)
	}

	route, err := db.GetRoute(
		lookup.Namespace,
		publicKey,
	)
	if err != nil {
		result.Status = "unreachable"
		result.Reason = "no active route"

		return replyLookup(session, result)
	}

	result.Found = true
	result.Address = route.Address
	result.ExpiresAt = route.ExpiresAt

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
// Daddy stores ciphertext only. It validates the envelope's signature and the
// identity of the peer that actually completed the handshake, but it can never
// read the subject or the body (SPEC section 43).
//
// A sibling Daddy forwarding on behalf of the original sender is also
// accepted: the envelope signature still proves the sender, and the forwarder
// is an authenticated peer whose identity is recorded for abuse tracing.
// The envelope itself is never re-signed or decrypted.
func handleHoldMessage(
	session *Session,
	local *identity.Identity,
	db *database.Database,
	data []byte,
) error {
	var envelope message.EncryptedMessage

	if err := json.Unmarshal(data, &envelope); err != nil {
		return replyHold(session, "", statusRejected, "malformed envelope")
	}

	if err := envelope.Verify(); err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	// Direct senders must prove they own the sender identity. Sibling
	// Daddies relaying a validly-signed envelope are accepted as forwarders
	// (SPEC v0.5 section 20): the envelope signature still authenticates the
	// original sender, and the forwarder is itself handshake-authenticated.
	if err := verifySessionIdentity(
		session,
		envelope.SenderNamespace,
		envelope.SenderPublicKey,
	); err != nil {
		if !isAuthenticatedForwarder(session, db, envelope) {
			return replyHold(session, envelope.ID, statusRejected, err.Error())
		}
	}

	// Message IDs are idempotent (SPEC section 26). Re-offering the same
	// logical message is not an error.
	alreadyStored, err := db.HeldMessageExists(envelope.ID)
	if err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	if alreadyStored {
		return replyHold(session, envelope.ID, statusAlreadyStored, "")
	}

	senderKey, err := decodeHexField(envelope.SenderPublicKey)
	if err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	recipientKey, err := decodeHexField(envelope.RecipientPublicKey)
	if err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	// Everything Daddy keeps is the opaque envelope. There is no plaintext
	// subject, body or key material in this record.
	payload, err := json.Marshal(envelope)
	if err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	now := time.Now().Unix()

	createdAt := envelope.CreatedAt
	if createdAt <= 0 || createdAt > now {
		createdAt = now
	}

	expiresAt := createdAt + HeldMessageTTL

	if err := db.StoreHeldMessage(
		envelope.ID,
		envelope.SenderNamespace,
		senderKey,
		envelope.RecipientNamespace,
		recipientKey,
		payload,
		createdAt,
		expiresAt,
	); err != nil {
		return replyHold(session, envelope.ID, statusRejected, err.Error())
	}

	// HOLD_ACK means "accepted", not "delivered" (SPEC section 24).
	if err := replyHold(session, envelope.ID, statusHeld, ""); err != nil {
		return err
	}

	// If the recipient is currently registered, Daddy can additionally try
	// to relay the ciphertext straight away (SPEC section 28). Failure is
	// harmless: the envelope stays held until the recipient asks for it.
	go relayHeldMessage(local, db, envelope)

	return nil
}

// replyDelivery sends a batch of encrypted envelopes to a recipient.
func replyDelivery(
	session *Session,
	envelopes []message.EncryptedMessage,
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

	// A node may only collect its own mail.
	if err := verifySessionIdentity(
		session,
		request.Namespace,
		request.PublicKey,
	); err != nil {
		return replyDelivery(session, nil)
	}

	recipientKey, err := decodeHexField(request.PublicKey)
	if err != nil {
		return replyDelivery(session, nil)
	}

	held, err := db.GetHeldMessagesForRecipient(
		recipientKey,
	)
	if err != nil {
		return fmt.Errorf(
			"get held messages: %w",
			err,
		)
	}

	now := time.Now().Unix()

	envelopes := make(
		[]message.EncryptedMessage,
		0,
		len(held),
	)

	for _, stored := range held {
		if len(envelopes) >= maxHeldMessageBatch {
			break
		}

		// Expired envelopes are never delivered; cleanup removes them.
		if stored.ExpiresAt <= now {
			continue
		}

		var envelope message.EncryptedMessage

		if err := json.Unmarshal(
			stored.Payload,
			&envelope,
		); err != nil {
			continue
		}

		envelopes = append(envelopes, envelope)
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

	switch ack.Status {
	case statusDelivered:
		if err := db.DeleteHeldMessage(
			ack.MessageID,
		); err != nil {
			return fmt.Errorf(
				"delete delivered message: %w",
				err,
			)
		}

	case statusRejected:
		// Keep the envelope. Daddy will retry until expires_at.

	default:
		return fmt.Errorf(
			"unknown delivery status %q",
			ack.Status,
		)
	}

	return sendAck(
		session,
		messageTypeDeleteAck,
		ack.MessageID,
		statusOK,
		"",
	)
}

// handleDeleteMessage lets a sender withdraw its own held message.
func handleDeleteMessage(
	session *Session,
	db *database.Database,
	data []byte,
) error {
	var request struct {
		MessageID string `json:"message_id"`
	}

	if err := json.Unmarshal(data, &request); err != nil {
		return fmt.Errorf(
			"unmarshal delete request: %w",
			err,
		)
	}

	if request.MessageID == "" {
		return errors.New(
			"delete request has no message ID",
		)
	}

	stored, err := db.GetHeldMessage(request.MessageID)
	if err != nil {
		return sendAck(
			session,
			messageTypeDeleteAck,
			request.MessageID,
			statusAlreadyStored,
			"message is not held",
		)
	}

	// Only the original sender may withdraw a held message.
	if err := verifySessionIdentity(
		session,
		stored.SenderNamespace,
		hex.EncodeToString(stored.SenderPublicKey),
	); err != nil {
		return sendAck(
			session,
			messageTypeDeleteAck,
			request.MessageID,
			statusRejected,
			err.Error(),
		)
	}

	if err := db.DeleteHeldMessage(
		request.MessageID,
	); err != nil {
		return sendAck(
			session,
			messageTypeDeleteAck,
			request.MessageID,
			statusRejected,
			err.Error(),
		)
	}

	return sendAck(
		session,
		messageTypeDeleteAck,
		request.MessageID,
		statusOK,
		"",
	)
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

	registration := routeRegistration{
		Namespace: local.Namespace,
		PublicKey: hex.EncodeToString(
			local.PublicKey,
		),
		EncryptionKey: hex.EncodeToString(
			local.EncryptionPublicKey,
		),
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
	local *identity.Identity,
	db *database.Database,
	namespace string,
	publicKey []byte,
) (*RemoteRoute, error) {
	if err := identity.ValidateNamespace(namespace); err != nil {
		return nil, err
	}

	if len(publicKey) == 0 {
		return nil, errors.New("lookup requires a public key")
	}

	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return nil, fmt.Errorf("connect to Daddy: %w", err)
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeLookupRoute,
		Data: marshalJSON(routeLookup{
			Namespace: namespace,
			PublicKey: hex.EncodeToString(publicKey),
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

	// Remember the peer's encryption key whenever Daddy publishes it.
	// This is what makes a first-contact send possible.
	if result.EncryptionKey != "" {
		if key, err := decodeHexField(
			result.EncryptionKey,
		); err == nil && len(key) > 0 {
			_ = db.RecordPeerIdentityWithKey(
				namespace,
				publicKey,
				key,
			)
		}
	}

	if !result.Found {
		return nil, fmt.Errorf(
			"Daddy has no route for %s: %s",
			namespace,
			result.Reason,
		)
	}

	if err := validateAdvertisedAddress(result.Address); err != nil {
		return nil, err
	}

	route := &RemoteRoute{
		Address:   result.Address,
		ExpiresAt: result.ExpiresAt,
	}

	if result.EncryptionKey != "" {
		route.EncryptionKey, _ = decodeHexField(
			result.EncryptionKey,
		)
	}

	// Cache the route locally so later sends avoid Daddy entirely. The new
	// registration supersedes any stale address (SPEC v0.5 Test I).
	if route.ExpiresAt > time.Now().Unix() {
		_ = db.RegisterOrReplaceRoute(
			namespace,
			publicKey,
			route.Address,
			route.ExpiresAt,
		)
	}

	return route, nil
}

// SendHoldMessage hands an encrypted envelope to Daddy for safe keeping
// (SPEC section 11). The reply is a HOLD_ACK, which only means "accepted".
func SendHoldMessage(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
	envelope *message.EncryptedMessage,
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

// forwardHoldMessage hands one held envelope to a sibling Daddy. It reuses
// the HOLD_MESSAGE exchange (ciphertext only) so a sibling can store or
// further relay it. already_stored counts as success: the sibling network
// already carries this ID and loops are avoided by message-ID idempotency.
func forwardHoldMessage(
	sibling string,
	local *identity.Identity,
	db *database.Database,
	envelope message.EncryptedMessage,
) error {
	return SendHoldMessage(sibling, local, db, &envelope)
}

// FetchHeldMessages collects encrypted envelopes held for this identity,
// verifies and decrypts them, and acknowledges each one (SPEC sections 23
// and 24). Daddy deletes a message only after a DELIVERY_ACK.
//
// It returns the number of envelopes that were successfully stored locally.
func FetchHeldMessages(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) (int, error) {
	session, err := Dial(daddyAddress, local, db)
	if err != nil {
		return 0, fmt.Errorf("connect to Daddy: %w", err)
	}

	defer session.Close()

	if err := sendMessage(session, Message{
		Type: messageTypeFetchMessages,
		Data: marshalJSON(fetchRequest{
			Namespace: local.Namespace,
			PublicKey: hex.EncodeToString(
				local.PublicKey,
			),
		}),
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
		status, reason := deliverEnvelopeLocally(
			db,
			local,
			envelope,
		)

		if err := sendAck(
			session,
			messageTypeDeliveryAck,
			envelope.ID,
			status,
			reason,
		); err != nil {
			return delivered, fmt.Errorf(
				"send delivery ack: %w",
				err,
			)
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
	envelope message.EncryptedMessage,
) error {
	session, err := Dial(address, local, db)
	if err != nil {
		return err
	}

	defer session.Close()

	// Cryptographic recipient validation (SPEC section 42): the node that
	// answered must be the holder of the recipient's identity key.
	if !sameBytes([]byte(session.Peer), recipientPublicKey) {
		return fmt.Errorf(
			"peer at %s is not the intended recipient",
			address,
		)
	}

	if err := sendMessage(session, Message{
		Type: messageTypeMessage,
		Data: marshalJSON(envelope),
	}); err != nil {
		return fmt.Errorf("send encrypted message: %w", err)
	}

	var response Message

	if err := receiveMessage(session, &response); err != nil {
		return fmt.Errorf("read message ack: %w", err)
	}

	if response.Type != messageTypeMessageAck {
		return fmt.Errorf(
			"unexpected delivery response %q",
			response.Type,
		)
	}

	var ack ackBody

	if err := json.Unmarshal(response.Data, &ack); err != nil {
		return fmt.Errorf("unmarshal message ack: %w", err)
	}

	if ack.MessageID != envelope.ID {
		return errors.New(
			"acknowledgement does not match the message",
		)
	}

	if ack.Status != statusDelivered {
		return fmt.Errorf(
			"recipient rejected message: %s",
			ack.Reason,
		)
	}

	return nil
}

// relayHeldMessage attempts an immediate relay of a stored envelope.
//
// Daddy runs this after answering HOLD_ACK. The ciphertext is forwarded
// unchanged (SPEC section 27), so Daddy never needs to decrypt anything. If
// the recipient is registered locally it is dialled directly; otherwise the
// envelope is forwarded to a sibling Daddy that may know the recipient
// (SPEC v0.5 section 20). If nothing can be completed the envelope simply
// stays held.
func relayHeldMessage(
	local *identity.Identity,
	db *database.Database,
	envelope message.EncryptedMessage,
) {
	recipientKey, err := decodeHexField(
		envelope.RecipientPublicKey,
	)
	if err != nil {
		return
	}

	if route, err := db.GetRoute(
		envelope.RecipientNamespace,
		recipientKey,
	); err == nil {
		if err := deliverEnvelopeToAddress(
			local,
			db,
			route.Address,
			recipientKey,
			envelope,
		); err == nil {
			_ = db.DeleteHeldMessage(envelope.ID)

			return
		}

		_ = db.DeleteRoute(
			envelope.RecipientNamespace,
			recipientKey,
			route.Address,
		)
	}

	forwardHeldToSiblingDaddies(local, db, envelope)
}

// resolveRecipient returns the recipient's encryption key and the freshest
// known direct route, if either is available locally.
func resolveRecipient(
	db *database.Database,
	namespace string,
	publicKey []byte,
) ([]byte, string) {
	var encryptionKey []byte

	if peer, err := db.GetPeerIdentity(
		namespace,
		publicKey,
	); err == nil {
		encryptionKey = peer.EncryptionPublicKey
	}

	address := ""

	if route, err := db.GetRoute(
		namespace,
		publicKey,
	); err == nil {
		address = route.Address
	}

	return encryptionKey, address
}

// SendResult describes how a message left the sender (SPEC section 39).
type SendResult struct {
	// Delivered is true when the recipient acknowledged the message.
	Delivered bool

	// Relayed is true when the message was handed to Daddy.
	Relayed bool

	// Address is the transport address of a successful direct delivery.
	Address string
}

// ResolveAndSend performs the complete ghost send flow.
func ResolveAndSend(
	local *identity.Identity,
	db *database.Database,
	recipientNamespace string,
	recipientPublicKey []byte,
	msg *message.Message,
) (*SendResult, error) {
	daddies := DaddyAddresses(db, DefaultRelaysPath())
	encryptionKey, directAddress := resolveRecipient(
		db,
		recipientNamespace,
		recipientPublicKey,
	)
	if directAddress == "" {
		route, key := lookupViaRelays(
			local,
			db,
			daddies,
			recipientNamespace,
			recipientPublicKey,
		)
		if route != nil {
			directAddress = route.Address
		}
		if len(encryptionKey) == 0 {
			encryptionKey = key
		}
	}
	if len(encryptionKey) == 0 {
		return nil, fmt.Errorf(
			"no encryption key known for %s::%s",
			recipientNamespace,
			identity.FingerprintFromHex(
				hex.EncodeToString(recipientPublicKey),
			),
		)
	}
	envelope, err := msg.EncryptForRecipient(
		encryptionKey,
		recipientNamespace,
		local.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("encrypt message: %w", err)
	}
	if directAddress != "" {
		if err := deliverEnvelopeToAddress(
			local,
			db,
			directAddress,
			recipientPublicKey,
			*envelope,
		); err == nil {
			return &SendResult{
				Delivered: true,
				Address:   directAddress,
			}, nil
		}
		_ = db.DeleteRoute(
			recipientNamespace,
			recipientPublicKey,
			directAddress,
		)
		_ = db.DeleteExpiredRoutes()
	}
	if holdViaRelays(local, db, daddies, envelope) {
		return &SendResult{Relayed: true}, nil
	}
	return nil, errors.New(
		"unable to deliver message: recipient is unreachable and Daddy is unavailable",
	)
}

// ---------------------------------------------------------------------------
// Daemon: route refresh, mail collection and cleanup
// ---------------------------------------------------------------------------

// StartCleanupRoutine removes expired held messages and expired routes on a
// fixed interval (SPEC sections 22 and 41). The returned function stops it.
func StartCleanupRoutine(db *database.Database) func() {
	done := make(chan struct{})
	ticker := time.NewTicker(DefaultCleanupPeriod)

	go func() {
		for {
			select {
			case <-ticker.C:
				_ = db.DeleteExpiredHeldMessages()
				_ = db.DeleteExpiredRoutes()

			case <-done:
				ticker.Stop()
				return
			}
		}
	}()

	return func() {
		close(done)
	}
}

// DialPersistent is the daemon-side Daddy loop. Despite the historical name
// there is no persistent peer session: it periodically opens a short-lived
// ghost connection, refreshes this node's route, collects any held messages
// and leaves. If Daddy is unreachable the loop keeps retrying and the node
// continues to work by direct delivery alone (SPEC section 7).
//
// Every configured relay is refreshed in turn, so disabling one Daddy does
// not strand the node (SPEC v0.5 section 19, Test F).
func DialPersistent(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) {
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
		return
	}

	for _, daddy := range daddies {
		if err := SetDaddyAddress(db, daddy); err != nil {
			fmt.Printf("Daddy: cannot store address: %v\n", err)
		}
	}

	stopCleanup := StartCleanupRoutine(db)
	defer stopCleanup()

	refresh := func() {
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

				continue
			}

			if err := collectHeldMessages(
				daddy,
				local,
				db,
			); err != nil {
				fmt.Printf(
					"Daddy %s: collecting held messages failed: %v\n",
					daddy,
					err,
				)
			}

			syncMailboxFromDaddyQuiet(daddy, local, db)
		}
	}

	// Register immediately, then refresh well before the TTL elapses.
	refresh()

	refreshTicker := time.NewTicker(DefaultRouteTTL / 2)
	defer refreshTicker.Stop()

	for range refreshTicker.C {
		refresh()
	}
}

// collectHeldMessages fetches and acknowledges any envelopes Daddy is holding
// for this identity (SPEC section 23).
//
// Every configured relay is tried in order; one dead Daddy never blocks
// collection from the others (SPEC v0.5 section 19, Test F).
func collectHeldMessages(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) error {
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

	delivered, err := fetchViaRelays(daddies, local, db)
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
