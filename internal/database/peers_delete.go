package database

import (
	"fmt"
)

// DeletePeerIdentity removes a peer entry, its alias and all cached routes
// in one transaction. Message history is kept: removing a contact must
// never delete the user's mail.
func (d *Database) DeletePeerIdentity(namespace string, publicKey []byte) error {
	tx, err := d.DB.Begin()
	if err != nil {
		return fmt.Errorf("begin peer deletion: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec(`
		DELETE FROM peer_routes WHERE namespace = ? AND public_key = ?
	`, namespace, publicKey); err != nil {
		return fmt.Errorf("delete peer routes: %w", err)
	}
	res, err := tx.Exec(`
		DELETE FROM peer_identities WHERE namespace = ? AND public_key = ?
	`, namespace, publicKey)
	if err != nil {
		return fmt.Errorf("delete peer identity: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete peer identity: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("peer identity not found")
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit peer deletion: %w", err)
	}
	committed = true
	return nil
}
