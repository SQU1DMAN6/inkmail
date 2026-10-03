package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const maxConfigBytes = 64 * 1024

type Limits struct {
	ConnectionsPerSource          int   `json:"connections_per_source"`
	ConnectionsGlobal             int   `json:"connections_global"`
	ConcurrentHandshakes          int   `json:"concurrent_handshakes"`
	ConcurrentRequests            int   `json:"concurrent_requests"`
	ConcurrentRequestsPerIdentity int   `json:"concurrent_requests_per_identity"`
	HandshakeFailuresPerWindow    int   `json:"handshake_failures_per_window"`
	HandshakeFailureWindowSeconds int   `json:"handshake_failure_window_seconds"`
	HandshakeCooldownSeconds      int   `json:"handshake_cooldown_seconds"`
	RequestsPerMinute             int   `json:"requests_per_minute"`
	RequestBurst                  int   `json:"request_burst"`
	HeldMessagesPerUser           int   `json:"held_messages_per_user"`
	HeldBytesPerUser              int64 `json:"held_bytes_per_user"`
	HeldMessagesPerMailbox        int   `json:"held_messages_per_mailbox"`
	HeldBytesPerMailbox           int64 `json:"held_bytes_per_mailbox"`
	HeldMessagesGlobal            int   `json:"held_messages_global"`
	HeldBytesGlobal               int64 `json:"held_bytes_global"`
	ReplayRecordsPerUser          int   `json:"replay_records_per_user"`
	ReplayRecordsGlobal           int   `json:"replay_records_global"`
	RoutesPerIdentity             int   `json:"routes_per_identity"`
	MailboxOwnersGlobal           int   `json:"mailbox_owners_global"`
	OutboxMessages                int   `json:"outbox_messages"`
	OutboxBytes                   int64 `json:"outbox_bytes"`
	PeerIdentitiesGlobal          int   `json:"peer_identities_global"`
	PeerRoutesGlobal              int   `json:"peer_routes_global"`
	PeerRoutesPerIdentity         int   `json:"peer_routes_per_identity"`
}

func Defaults() Limits {
	return Limits{
		ConnectionsPerSource:          8,
		ConnectionsGlobal:             256,
		ConcurrentHandshakes:          64,
		ConcurrentRequests:            64,
		ConcurrentRequestsPerIdentity: 8,
		HandshakeFailuresPerWindow:    5,
		HandshakeFailureWindowSeconds: 60,
		HandshakeCooldownSeconds:      60,
		RequestsPerMinute:             600,
		RequestBurst:                  300,
		HeldMessagesPerUser:           256,
		HeldBytesPerUser:              32 * 1024 * 1024,
		HeldMessagesPerMailbox:        512,
		HeldBytesPerMailbox:           64 * 1024 * 1024,
		HeldMessagesGlobal:            100000,
		HeldBytesGlobal:               8 * 1024 * 1024 * 1024,
		ReplayRecordsPerUser:          4096,
		ReplayRecordsGlobal:           1000000,
		RoutesPerIdentity:             32,
		MailboxOwnersGlobal:           100000,
		OutboxMessages:                1000,
		OutboxBytes:                   128 * 1024 * 1024,
		PeerIdentitiesGlobal:          100000,
		PeerRoutesGlobal:              100000,
		PeerRoutesPerIdentity:         8,
	}
}

func Load(path string) (Limits, error) {
	limits := Defaults()
	if path == "" {
		return limits, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return Limits{}, fmt.Errorf("read resource configuration: %w", err)
	}
	if len(data) == 0 || len(data) > maxConfigBytes {
		return Limits{}, fmt.Errorf("resource configuration must be between 1 and %d bytes", maxConfigBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&limits); err != nil {
		return Limits{}, fmt.Errorf("decode resource configuration: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return Limits{}, fmt.Errorf("resource configuration contains multiple JSON values")
		}
		return Limits{}, fmt.Errorf("decode trailing resource configuration: %w", err)
	}
	if err := limits.Validate(); err != nil {
		return Limits{}, err
	}
	return limits, nil
}

func (limits Limits) Validate() error {
	checks := []struct {
		name    string
		value   int64
		minimum int64
		maximum int64
	}{
		{"connections_per_source", int64(limits.ConnectionsPerSource), 1, 64},
		{"connections_global", int64(limits.ConnectionsGlobal), 1, 512},
		{"concurrent_handshakes", int64(limits.ConcurrentHandshakes), 1, 256},
		{"concurrent_requests", int64(limits.ConcurrentRequests), 1, 128},
		{"concurrent_requests_per_identity", int64(limits.ConcurrentRequestsPerIdentity), 1, 32},
		{"handshake_failures_per_window", int64(limits.HandshakeFailuresPerWindow), 1, 100},
		{"handshake_failure_window_seconds", int64(limits.HandshakeFailureWindowSeconds), 1, 3600},
		{"handshake_cooldown_seconds", int64(limits.HandshakeCooldownSeconds), 1, 3600},
		{"requests_per_minute", int64(limits.RequestsPerMinute), 1, 60000},
		{"request_burst", int64(limits.RequestBurst), 272, 10000},
		{"held_messages_per_user", int64(limits.HeldMessagesPerUser), 1, 4096},
		{"held_bytes_per_user", limits.HeldBytesPerUser, 1, 128 * 1024 * 1024},
		{"held_messages_per_mailbox", int64(limits.HeldMessagesPerMailbox), 1, 8192},
		{"held_bytes_per_mailbox", limits.HeldBytesPerMailbox, 1, 512 * 1024 * 1024},
		{"held_messages_global", int64(limits.HeldMessagesGlobal), 1, 1000000},
		{"held_bytes_global", limits.HeldBytesGlobal, 1, 8 * 1024 * 1024 * 1024},
		{"replay_records_per_user", int64(limits.ReplayRecordsPerUser), 1, 100000},
		{"replay_records_global", int64(limits.ReplayRecordsGlobal), 1, 2000000},
		{"routes_per_identity", int64(limits.RoutesPerIdentity), 1, 1024},
		{"mailbox_owners_global", int64(limits.MailboxOwnersGlobal), 1, 500000},
		{"outbox_messages", int64(limits.OutboxMessages), 1, 100000},
		{"outbox_bytes", limits.OutboxBytes, 1, 1024 * 1024 * 1024},
		{"peer_identities_global", int64(limits.PeerIdentitiesGlobal), 1, 500000},
		{"peer_routes_global", int64(limits.PeerRoutesGlobal), 1, 500000},
		{"peer_routes_per_identity", int64(limits.PeerRoutesPerIdentity), 1, 64},
	}
	for _, check := range checks {
		if check.value < check.minimum || check.value > check.maximum {
			return fmt.Errorf("resource limit %s must be between %d and %d", check.name, check.minimum, check.maximum)
		}
	}
	if limits.ConnectionsPerSource > limits.ConnectionsGlobal {
		return fmt.Errorf("connections_per_source cannot exceed connections_global")
	}
	if limits.ConcurrentHandshakes > limits.ConnectionsGlobal {
		return fmt.Errorf("concurrent_handshakes cannot exceed connections_global")
	}
	if limits.ConcurrentRequests > limits.ConnectionsGlobal {
		return fmt.Errorf("concurrent_requests cannot exceed connections_global")
	}
	if limits.ConcurrentRequestsPerIdentity > limits.ConcurrentRequests {
		return fmt.Errorf("concurrent_requests_per_identity cannot exceed concurrent_requests")
	}
	return nil
}
