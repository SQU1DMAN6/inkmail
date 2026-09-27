package main

// peers.go implements the `peers` subcommand family:
//
//	peers               -> peers list (default)
//	peers list          -> number, identity, alias, status, reachability
//	peers add <contact> -> register keys and opaque mailbox ID
//	peers remove <num>  -> remove peer entry + alias + cached routes
//	peers alias <n> <a> -> set/replace a friendly alias
//
// Display numbers are ephemeral (assigned at display time from the same
// deterministic ordering as `send`); only the alias is stored.

import (
	"fmt"
	"strings"
)

// handlePeersCommand dispatches `peers [subcommand ...]`.
// Bare `peers` defaults to `peers list`.
func (c *Client) handlePeersCommand(args []string) {
	if len(args) == 0 || strings.EqualFold(args[0], "list") {
		if len(args) > 1 {
			fmt.Println("Usage: peers list")
			return
		}
		c.listPeers()
		return
	}
	switch strings.ToLower(args[0]) {
	case "add":
		if len(args) != 2 {
			fmt.Println("Usage: peers add <namespace::ed25519-key::x25519-key::mailbox-id>")
			return
		}
		c.addPeer(args[1])
	case "remove", "rm", "del":
		if len(args) != 2 {
			fmt.Println("Usage: peers remove <number>")
			return
		}
		c.removePeer(args[1])
	case "alias":
		if len(args) != 3 {
			fmt.Println("Usage: peers alias <number> <alias>")
			fmt.Println("       peers alias <number> --clear   (remove alias)")
			return
		}
		c.setPeerAlias(args[1], args[2])
	case "help", "-h", "--help":
		c.printPeersHelp()
	default:
		fmt.Printf("Unknown peers subcommand %q.\n", args[0])
		c.printPeersHelp()
	}
}

func (c *Client) printPeersHelp() {
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  peers                  List peers (default)")
	fmt.Println("  peers list             List peers, aliases, status, reachability")
	fmt.Println("  peers add <contact>    Register identity keys and opaque mailbox ID")
	fmt.Println("  peers remove <number>  Remove a peer entry, alias and cached routes")
	fmt.Println("  peers alias <n> <a>    Set friendly alias for peer number n")
	fmt.Println("  peers alias <n> --clear  Remove the alias")
	fmt.Println()
}
