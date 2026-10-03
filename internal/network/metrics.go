package network

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
)

type runtimeCounters struct {
	rejectedConnections  atomic.Uint64
	rejectedHandshakes   atomic.Uint64
	failedHandshakes     atomic.Uint64
	authenticatedSession atomic.Int64
	rejectedRequests     atomic.Uint64
	rateLimitEvents      atomic.Uint64
	acceptedMessages     atomic.Uint64
	rejectedMessages     atomic.Uint64
	acceptedBytes        atomic.Uint64
	rejectedBytes        atomic.Uint64
	replayRejections     atomic.Uint64
	expiredEnvelopes     atomic.Uint64
	expiredPeerRoutes    atomic.Uint64
}

var runtimeStats runtimeCounters

type RuntimeMetrics struct {
	ActiveConnections     int
	RejectedConnections   uint64
	ActiveHandshakes      int
	RejectedHandshakes    uint64
	FailedHandshakes      uint64
	AuthenticatedSessions int64
	ActiveRequests        int
	RejectedRequests      uint64
	RateLimitEvents       uint64
	AcceptedMessages      uint64
	RejectedMessages      uint64
	AcceptedBytes         uint64
	RejectedBytes         uint64
	ReplayRejections      uint64
	ExpiredEnvelopes      uint64
	ExpiredPeerRoutes     uint64
	MailboxMessages       int64
	MailboxBytes          int64
	ReplayRecords         int64
	MailboxRoutes         int64
	MailboxOwners         int64
	PeerIdentities        int64
	PeerRoutes            int64
	OutboxMessages        int64
	OutboxBytes           int64
	LegacyRelayRecords    int64
	LegacyRelayBytes      int64
}

func SnapshotResourceMetrics(db *database.Database) (RuntimeMetrics, error) {
	inboundConnections.Lock()
	activeConnections := inboundConnections.global
	inboundConnections.Unlock()
	usage, err := db.ResourceUsage()
	if err != nil {
		return RuntimeMetrics{}, err
	}
	return RuntimeMetrics{
		ActiveConnections:     activeConnections,
		RejectedConnections:   runtimeStats.rejectedConnections.Load(),
		ActiveHandshakes:      len(handshakeSlots),
		RejectedHandshakes:    runtimeStats.rejectedHandshakes.Load(),
		FailedHandshakes:      runtimeStats.failedHandshakes.Load(),
		AuthenticatedSessions: runtimeStats.authenticatedSession.Load(),
		ActiveRequests:        inFlightRequests.count(),
		RejectedRequests:      runtimeStats.rejectedRequests.Load(),
		RateLimitEvents:       runtimeStats.rateLimitEvents.Load(),
		AcceptedMessages:      runtimeStats.acceptedMessages.Load(),
		RejectedMessages:      runtimeStats.rejectedMessages.Load(),
		AcceptedBytes:         runtimeStats.acceptedBytes.Load(),
		RejectedBytes:         runtimeStats.rejectedBytes.Load(),
		ReplayRejections:      runtimeStats.replayRejections.Load(),
		ExpiredEnvelopes:      runtimeStats.expiredEnvelopes.Load(),
		ExpiredPeerRoutes:     runtimeStats.expiredPeerRoutes.Load(),
		MailboxMessages:       usage.HeldMessages,
		MailboxBytes:          usage.HeldBytes,
		ReplayRecords:         usage.ReplayRecords,
		MailboxRoutes:         usage.MailboxRoutes,
		MailboxOwners:         usage.MailboxOwners,
		PeerIdentities:        usage.PeerIdentities,
		PeerRoutes:            usage.PeerRoutes,
		OutboxMessages:        usage.OutboxMessages,
		OutboxBytes:           usage.OutboxBytes,
		LegacyRelayRecords:    usage.LegacyRelayRecords,
		LegacyRelayBytes:      usage.LegacyRelayBytes,
	}, nil
}

func ReportResourceMetrics(ctx context.Context, db *database.Database) {
	printSnapshot := func() {
		metrics, err := SnapshotResourceMetrics(db)
		if err != nil {
			fmt.Printf("InkMail resource metrics unavailable: %v\n", err)
			return
		}
		fmt.Printf(
			"InkMail resource metrics: connections=%d rejected_connections=%d handshakes=%d rejected_handshakes=%d failed_handshakes=%d sessions=%d requests=%d rejected_requests=%d rate_limited=%d messages_accepted=%d messages_rejected=%d bytes_accepted=%d bytes_rejected=%d replay_rejected=%d held_messages=%d held_bytes=%d replay_records=%d mailbox_routes=%d mailbox_owners=%d outbox_messages=%d outbox_bytes=%d peer_identities=%d peer_routes=%d legacy_records=%d legacy_bytes=%d expired=%d expired_peer_routes=%d\n",
			metrics.ActiveConnections,
			metrics.RejectedConnections,
			metrics.ActiveHandshakes,
			metrics.RejectedHandshakes,
			metrics.FailedHandshakes,
			metrics.AuthenticatedSessions,
			metrics.ActiveRequests,
			metrics.RejectedRequests,
			metrics.RateLimitEvents,
			metrics.AcceptedMessages,
			metrics.RejectedMessages,
			metrics.AcceptedBytes,
			metrics.RejectedBytes,
			metrics.ReplayRejections,
			metrics.MailboxMessages,
			metrics.MailboxBytes,
			metrics.ReplayRecords,
			metrics.MailboxRoutes,
			metrics.MailboxOwners,
			metrics.OutboxMessages,
			metrics.OutboxBytes,
			metrics.PeerIdentities,
			metrics.PeerRoutes,
			metrics.LegacyRelayRecords,
			metrics.LegacyRelayBytes,
			metrics.ExpiredEnvelopes,
			metrics.ExpiredPeerRoutes,
		)
	}

	printSnapshot()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			printSnapshot()
		case <-ctx.Done():
			return
		}
	}
}
