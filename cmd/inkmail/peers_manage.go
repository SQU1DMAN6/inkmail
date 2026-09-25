package main

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

// addPeer registers a new peer identity from a canonical Peer ID.
// It requires the FULL Ed25519 public key; fingerprints are rejected by
// database.ParsePeerID with a helpful message.
func (c *Client) addPeer(raw string) {
	namespace, key, err := database.ParsePeerID(raw)
	if err != nil {
		fmt.Printf("peers add: %v\n", err)
		return
	}
	// Refuse to add our own identity as a peer.
	if namespace == c.Identity.Namespace &&
		len(key) == len(c.Identity.PublicKey) &&
		string(key) == string(c.Identity.PublicKey) {
		fmt.Println("peers add: that is your own identity; not added.")
		return
	}
	// Idempotent: already known -> report its number instead of erroring.
	if peers, err := c.Database.ListPeerIdentities(); err == nil {
		for i := range peers {
			if peers[i].Namespace == namespace &&
				string(peers[i].PublicKey) == string(key) {
				fmt.Printf("Peer already known as %d (%s).\n", i+1, peerDisplayIdentity(&peers[i]))
				return
			}
		}
	}
	if err := c.Database.RecordPeerIdentity(namespace, key); err != nil {
		fmt.Printf("peers add: %v\n", err)
		return
	}
	peers, err := c.Database.ListPeerIdentities()
	if err != nil {
		fmt.Printf("peers add: %v\n", err)
		return
	}
	number := -1
	for i := range peers {
		if peers[i].Namespace == namespace && string(peers[i].PublicKey) == string(key) {
			number = i + 1
			break
		}
	}
	fmt.Printf(
		"Added peer %d: %s::%s\n",
		number,
		namespace,
		identity.FingerprintFromHex(hex.EncodeToString(key)),
	)
	fmt.Println("Set a friendly name with: peers alias <number> <alias>")
	fmt.Println("The encryption key is fetched automatically via Daddy on first send.")
}

// removePeer deletes a peer entry, its alias and its cached routes.
func (c *Client) removePeer(raw string) {
	peer, _, err := c.resolvePeerNumber(raw)
	if err != nil {
		fmt.Printf("peers remove: %v\n", err)
		return
	}
	label := peerDisplayIdentity(peer)
	if peer.Alias != "" {
		label += fmt.Sprintf(" (alias %q)", peer.Alias)
	}
	if err := c.Database.DeletePeerIdentity(peer.Namespace, peer.PublicKey); err != nil {
		fmt.Printf("peers remove: %v\n", err)
		return
	}
	fmt.Printf("Removed peer %s.\n", label)
	fmt.Println("Message history is kept; cached routes for this peer were dropped.")
}

// setPeerAlias assigns, replaces or clears a peer's friendly alias.
func (c *Client) setPeerAlias(numberRaw, aliasRaw string) {
	peer, _, err := c.resolvePeerNumber(numberRaw)
	if err != nil {
		fmt.Printf("peers alias: %v\n", err)
		return
	}
	alias := strings.TrimSpace(aliasRaw)
	if strings.EqualFold(alias, "--clear") || alias == "-" || strings.EqualFold(alias, "clear") {
		alias = ""
	}
	if alias == "" {
		if err := c.Database.SetPeerAlias(peer.Namespace, peer.PublicKey, ""); err != nil {
			fmt.Printf("peers alias: %v\n", err)
			return
		}
		fmt.Printf("Cleared alias for peer %s.\n", peerDisplayIdentity(peer))
		return
	}
	if err := c.Database.SetPeerAlias(peer.Namespace, peer.PublicKey, alias); err != nil {
		fmt.Printf("peers alias: %v\n", err)
		return
	}
	fmt.Printf("Peer %s is now known as %q.\n", peerDisplayIdentity(peer), alias)
	fmt.Printf("Send with: send (then enter %s)\n", alias)
}
