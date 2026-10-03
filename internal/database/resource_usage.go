package database

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

var legacyRelayTables = []string{
	"held_messages",
	"mailbox_messages",
	"mailbox_ops",
	"delivery_receipts",
	"delivery_receipt_outbox",
}

type ResourceUsage struct {
	HeldMessages       int64
	HeldBytes          int64
	ReplayRecords      int64
	MailboxRoutes      int64
	MailboxOwners      int64
	OutboxMessages     int64
	OutboxBytes        int64
	PeerIdentities     int64
	PeerRoutes         int64
	LegacyRelayRecords int64
	LegacyRelayBytes   int64
}

func ensurePeerIdentityCapacity(tx *sql.Tx, namespace string, publicKey []byte, limit int) error {
	var exists int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM peer_identities WHERE namespace = ? AND public_key = ?`, namespace, publicKey).Scan(&exists); err != nil {
		return fmt.Errorf("check existing peer identity: %w", err)
	}
	if exists != 0 {
		return nil
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM peer_identities`).Scan(&count); err != nil {
		return fmt.Errorf("count peer identities: %w", err)
	}
	if count >= limit {
		return fmt.Errorf("peer identity quota exceeded")
	}
	return nil
}

func (d *Database) loadLegacyRelayUsage() error {
	var records, bytes int64
	for _, table := range legacyRelayTables {
		var exists int
		if err := d.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
			return fmt.Errorf("check legacy relay table %s: %w", table, err)
		}
		if exists == 0 {
			continue
		}
		query, err := legacyStorageUsageQuery(d.DB, table)
		if err != nil {
			return fmt.Errorf("inspect legacy relay table %s: %w", table, err)
		}
		var tableRecords, tableBytes int64
		if err := d.DB.QueryRow(query).Scan(&tableRecords, &tableBytes); err != nil {
			return fmt.Errorf("account legacy relay table %s: %w", table, err)
		}
		records += tableRecords
		bytes += tableBytes
	}
	d.legacyRelayMessages = records
	d.legacyRelayBytes = bytes
	return nil
}

func legacyStorageUsageQuery(db *sql.DB, table string) (string, error) {
	columns, err := db.Query(`PRAGMA table_info(` + quoteIdentifier(table) + `)`)
	if err != nil {
		return "", err
	}
	defer columns.Close()
	var expressions []string
	for columns.Next() {
		var index, notNull, primaryKey int
		var name, dataType string
		var defaultValue any
		if err := columns.Scan(&index, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			return "", err
		}
		expressions = append(expressions, "COALESCE(length(CAST("+quoteIdentifier(name)+" AS BLOB)), 0)")
	}
	if err := columns.Err(); err != nil {
		return "", err
	}
	if len(expressions) == 0 {
		return "SELECT COUNT(*), COALESCE(SUM(64), 0) FROM " + quoteIdentifier(table), nil
	}
	return "SELECT COUNT(*), COALESCE(SUM(64 + " + strings.Join(expressions, " + ") + "), 0) FROM " + quoteIdentifier(table), nil
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

func (d *Database) ResourceUsage() (ResourceUsage, error) {
	usage := ResourceUsage{
		LegacyRelayRecords: d.legacyRelayMessages,
		LegacyRelayBytes:   d.legacyRelayBytes,
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM opaque_held_messages`).Scan(&usage.HeldMessages, &usage.HeldBytes); err != nil {
		return ResourceUsage{}, fmt.Errorf("count held-envelope usage: %w", err)
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*) FROM opaque_envelope_dedup WHERE expires_at > ?`, time.Now().Unix()).Scan(&usage.ReplayRecords); err != nil {
		return ResourceUsage{}, fmt.Errorf("count replay-record usage: %w", err)
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*) FROM mailbox_routes WHERE expires_at > ?`, time.Now().Unix()).Scan(&usage.MailboxRoutes); err != nil {
		return ResourceUsage{}, fmt.Errorf("count active mailbox routes: %w", err)
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*) FROM mailbox_owners`).Scan(&usage.MailboxOwners); err != nil {
		return ResourceUsage{}, fmt.Errorf("count mailbox owners: %w", err)
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*), COALESCE(SUM(length(payload)), 0) FROM opaque_mailbox_outbox`).Scan(&usage.OutboxMessages, &usage.OutboxBytes); err != nil {
		return ResourceUsage{}, fmt.Errorf("count opaque outbox usage: %w", err)
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*) FROM peer_identities`).Scan(&usage.PeerIdentities); err != nil {
		return ResourceUsage{}, fmt.Errorf("count peer identities: %w", err)
	}
	if err := d.DB.QueryRow(`SELECT COUNT(*) FROM peer_routes WHERE expires_at > ?`, time.Now().Unix()).Scan(&usage.PeerRoutes); err != nil {
		return ResourceUsage{}, fmt.Errorf("count active peer routes: %w", err)
	}
	return usage, nil
}
