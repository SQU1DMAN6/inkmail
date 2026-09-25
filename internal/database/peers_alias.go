package database

import (
	"fmt"
	"strings"
)

// SetPeerAlias assigns (or replaces) the friendly name of a known peer.
// An empty alias clears the current name. Uniqueness is case-insensitive.
func (d *Database) SetPeerAlias(namespace string, publicKey []byte, alias string) error {
	alias = strings.TrimSpace(alias)
	if alias != "" {
		if err := ValidateAlias(alias); err != nil {
			return err
		}
		var ownerNS string
		var ownerKey []byte
		err := d.DB.QueryRow(`
			SELECT namespace, public_key FROM peer_identities
			WHERE alias = ? COLLATE NOCASE
		`, alias).Scan(&ownerNS, &ownerKey)
		if err == nil {
			if ownerNS != namespace || !bytesEqual(ownerKey, publicKey) {
				return fmt.Errorf("alias %q is already used by %s; pick another name", alias, ownerNS)
			}
		}
		if peers, err := d.ListPeerIdentities(); err == nil {
			for i := range peers {
				if strings.EqualFold(peers[i].Namespace, alias) &&
					(peers[i].Namespace != namespace || !bytesEqual(peers[i].PublicKey, publicKey)) {
					return fmt.Errorf("alias %q collides with another peer's namespace; pick another name", alias)
				}
			}
		}
	}
	res, err := d.DB.Exec(`
		UPDATE peer_identities SET alias = ? WHERE namespace = ? AND public_key = ?
	`, alias, namespace, publicKey)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return fmt.Errorf("alias %q is already in use; pick another name", alias)
		}
		return fmt.Errorf("set peer alias: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("set peer alias: %w", err)
	}
	if affected == 0 {
		return fmt.Errorf("peer identity not found")
	}
	return nil
}
