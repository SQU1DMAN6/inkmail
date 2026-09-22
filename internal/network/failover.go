package network

// failover.go tries each configured relay in turn so one dead Daddy never blocks a send, lookup or fetch (SPEC v0.5 sections 18, 19, Tests E/F).

import (
	"strconv"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

// lookupViaRelays tries each relay in order until one resolves the identity.
// It returns the first usable route (cached locally) plus the encryption key
// learned from that relay, if any.
func lookupViaRelays(
	local *identity.Identity,
	db *database.Database,
	daddies []string,
	namespace string,
	publicKey []byte,
) (*RemoteRoute, []byte) {
	for _, daddy := range daddies {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		route, err := LookupRouteWithDaddy(
			daddy,
			local,
			db,
			namespace,
			publicKey,
		)
		if err != nil || route == nil {
			continue
		}

		return route, route.EncryptionKey
	}

	return nil, nil
}

// holdViaRelays hands the envelope to the first relay that answers HOLD_ACK.
// HOLD_ACK means "accepted", never "received" (SPEC v0.5 section 11).
func holdViaRelays(
	local *identity.Identity,
	db *database.Database,
	daddies []string,
	envelope *message.EncryptedMessage,
) bool {
	for _, daddy := range daddies {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		if err := SendHoldMessage(daddy, local, db, envelope); err == nil {
			return true
		}
	}

	return false
}

// fetchViaRelays collects held envelopes from each relay in turn. It returns
// the total stored locally; one dead Daddy must not block the others.
func fetchViaRelays(
	daddies []string,
	local *identity.Identity,
	db *database.Database,
) (int, error) {
	total := 0

	var lastErr error

	for _, daddy := range daddies {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		delivered, err := FetchHeldMessages(daddy, local, db)
		if err != nil {
			lastErr = err

			continue
		}

		total += delivered
	}

	if total == 0 && lastErr != nil {
		return 0, lastErr
	}

	return total, nil
}

// forwardHeldToSiblingDaddies implements Daddy-to-Daddy relay (SPEC v0.5
// section 20). The envelope stays end-to-end encrypted; a sibling only sees
// routing metadata. A sibling that already holds the ID answers
// already_stored, which counts as success and stops further forwarding.
func forwardHeldToSiblingDaddies(local *identity.Identity, db *database.Database, envelope message.EncryptedMessage) {
	for _, sibling := range DaddyAddresses(db, DefaultRelaysPath()) {
		if strings.TrimSpace(sibling) == "" {
			continue
		}
		if err := forwardHoldMessage(sibling, local, db, envelope); err == nil {
			return
		}
	}
}

// isAuthenticatedForwarder reports whether the handshake-authenticated peer
// may relay an envelope it did not author. The envelope signature was
// already verified by the caller, so authorship is proven; here we only
// require a real authenticated peer (never anonymous) and record it.
func isAuthenticatedForwarder(session *Session, db *database.Database, envelope message.EncryptedMessage) bool {
	if session == nil || len(session.Peer) == 0 {
		return false
	}
	if strings.TrimSpace(session.PeerNamespace) == "" {
		return false
	}
	_ = db.RecordPeerIdentityWithKey(session.PeerNamespace, []byte(session.Peer), session.PeerEncryptionKey)
	return envelope.Verify() == nil
}

// syncMailboxFromDaddyQuiet pulls verified ops in the background daemon.
// Failures are silent: the next tick or manual `msg sync` retries.
func syncMailboxFromDaddyQuiet(
	daddyAddress string,
	local *identity.Identity,
	db *database.Database,
) {
	raw, err := db.GetMeta("mailbox_since")
	if err != nil {
		return
	}

	raw = strings.TrimSpace(raw)

	var since int64

	if raw != "" {
		since, err = strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return
		}
	}

	next, err := mailboxSyncFromDaddy(daddyAddress, local, db, since)
	if err != nil {
		return
	}

	_ = db.SetMeta("mailbox_since", strconv.FormatInt(next, 10))
}
