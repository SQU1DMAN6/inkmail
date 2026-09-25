package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
)

// resolveSendRecipient maps the user's recipient input to a stored peer.
// Order: display number -> alias (case-insensitive) -> full/fingerprint
// identity -> namespace. Alias is checked BEFORE namespace so a friendly
// name stays unambiguous even if it resembles a namespace.
func (c *Client) resolveSendRecipient(selection string, peers []database.PeerIdentity) (*database.PeerIdentity, error) {
	selection = strings.TrimSpace(selection)
	if selection == "" {
		return nil, fmt.Errorf("no peer selected")
	}
	// 1. Display number (ephemeral, 1-based).
	if num, err := strconv.Atoi(selection); err == nil {
		if num < 1 || num > len(peers) {
			return nil, fmt.Errorf("peer number %d out of range (1-%d)", num, len(peers))
		}
		peer := peers[num-1]
		return &peer, nil
	}
	// 2. Alias (case-insensitive exact match).
	for i := range peers {
		if peers[i].Alias != "" && strings.EqualFold(selection, peers[i].Alias) {
			peer := peers[i]
			return &peer, nil
		}
	}
	// 3. Full identity or fingerprint: namespace::hex.
	for i := range peers {
		fingerprint := hex.EncodeToString(peers[i].PublicKey[:8])
		full := hex.EncodeToString(peers[i].PublicKey)
		for _, candidate := range []string{
			fmt.Sprintf("%s::%s", peers[i].Namespace, fingerprint),
			fmt.Sprintf("%s::%s", peers[i].Namespace, full),
		} {
			if strings.EqualFold(selection, candidate) {
				peer := peers[i]
				return &peer, nil
			}
		}
	}
	// 4. Namespace-only fuzzy match (legacy behaviour).
	for i := range peers {
		if strings.EqualFold(selection, peers[i].Namespace) {
			peer := peers[i]
			return &peer, nil
		}
	}
	return nil, fmt.Errorf("peer %q not found (try number, alias or namespace::key)", selection)
}
