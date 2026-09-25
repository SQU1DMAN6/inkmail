package main

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

// resolvePeerNumber maps an ephemeral display number to a stored peer using
// the same deterministic ordering as the list view.
func (c *Client) resolvePeerNumber(raw string) (*database.PeerIdentity, int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return nil, 0, fmt.Errorf("invalid peer number %q: expected peers remove <number>", raw)
	}
	peers, err := c.Database.ListPeerIdentities()
	if err != nil {
		return nil, 0, fmt.Errorf("list peers: %w", err)
	}
	if n < 1 || n > len(peers) {
		return nil, len(peers), fmt.Errorf("peer number %d out of range (1-%d)", n, len(peers))
	}
	peer := peers[n-1]
	return &peer, len(peers), nil
}

// peerDisplayIdentity renders namespace::fingerprint.
func peerDisplayIdentity(peer *database.PeerIdentity) string {
	fingerprint := identity.FingerprintFromHex(hex.EncodeToString(peer.PublicKey))
	return fmt.Sprintf("%s::%s", peer.Namespace, fingerprint)
}

// peerStatus is a local-only summary: whether we hold an encryption key for
// the peer and when the identity was last seen. No network I/O happens here
// so `peers list` stays instant and never stalls on a dead route.
func peerStatus(peer *database.PeerIdentity) string {
	parts := []string{"known"}
	if len(peer.EncryptionPublicKey) > 0 {
		parts = append(parts, "enc-key:yes")
	} else {
		parts = append(parts, "enc-key:no")
	}
	if peer.LastSeen > 0 {
		age := time.Since(time.Unix(peer.LastSeen, 0)).Round(time.Second)
		if age < 0 {
			age = 0
		}
		parts = append(parts, "seen:"+age.String()+"-ago")
	}
	return strings.Join(parts, " ")
}

// peerReachability reports only what the LOCAL route cache knows:
// a fresh cached route vs. no cached route (resolved via Daddy on send).
func (c *Client) peerReachability(peer *database.PeerIdentity) string {
	routes, err := c.Database.ListRoutes(peer.Namespace, peer.PublicKey)
	if err != nil || len(routes) == 0 {
		return "no-cached-route (Daddy on send)"
	}
	fresh := 0
	for i := range routes {
		if routes[i].ExpiresAt > time.Now().Unix() {
			fresh++
		}
	}
	if fresh == 0 {
		return "routes-expired (Daddy on send)"
	}
	return fmt.Sprintf("direct:cached (%d route(s))", fresh)
}

// listPeers prints number, identity, alias, status and reachability.
func (c *Client) listPeers() {
	peers, err := c.Database.ListPeerIdentities()
	if err != nil {
		fmt.Printf("list peers: %v\n", err)
		return
	}
	if len(peers) == 0 {
		fmt.Println()
		fmt.Println("No known peers.")
		fmt.Println()
		fmt.Println("Add one with: peers add <namespace::full-public-key-hex>")
		fmt.Println()
		return
	}
	fmt.Println()
	fmt.Printf("%-4s  %-28s  %-14s  %-28s  %s\n", "NUM", "IDENTITY", "ALIAS", "STATUS", "REACHABILITY")
	for i := range peers {
		alias := peers[i].Alias
		if alias == "" {
			alias = "-"
		}
		fmt.Printf("%-4d  %-28s  %-14s  %-28s  %s\n",
			i+1,
			peerDisplayIdentity(&peers[i]),
			alias,
			peerStatus(&peers[i]),
			c.peerReachability(&peers[i]),
		)
	}
	fmt.Println()
	fmt.Printf("%d peer(s)\n", len(peers))
	fmt.Println()
}
