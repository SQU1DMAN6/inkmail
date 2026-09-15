package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
	"github.com/SQU1DMAN6/inkmail/internal/network"
)

func main() {
	dataDir := flag.String(
		"data",
		filepath.Join(
			os.Getenv("HOME"),
			".inkmail",
		),
		"InkMail data directory",
	)

	namespace := flag.String(
		"user",
		"",
		"identity namespace used on first launch",
	)

	flag.Parse()

	if err := os.MkdirAll(
		*dataDir,
		0700,
	); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"create data directory: %v\n",
			err,
		)
		os.Exit(1)
	}

	id, err := identity.LoadOrCreate(
		filepath.Join(
			*dataDir,
			"identity",
		),
		*namespace,
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"load identity: %v\n",
			err,
		)
		os.Exit(1)
	}

	db, err := database.Open(
		filepath.Join(
			*dataDir,
			"node.db",
		),
	)
	if err != nil {
		fmt.Fprintf(
			os.Stderr,
			"open database: %v\n",
			err,
		)
		os.Exit(1)
	}

	defer db.DB.Close()

	fmt.Println()
	fmt.Println("InkMail")
	fmt.Printf(
		"Identity: %s\n",
		identity.Address(id),
	)
	fmt.Println()
	fmt.Println(
		"Type 'help' for available commands.",
	)
	fmt.Println()

	client := &Client{
		Identity: id,
		Database: db,
	}

	client.repl()
}

type Client struct {
	Identity *identity.Identity
	Database *database.Database
	Session  *network.Session
}

func (c *Client) repl() {
	reader := bufio.NewReader(
		os.Stdin,
	)

	for {
		fmt.Print("inkmail> ")

		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println()
			c.closeSession()
			return
		}

		input = strings.TrimSpace(input)

		if input == "" {
			continue
		}

		if c.handleCommand(
			reader,
			input,
		) {
			c.closeSession()
			return
		}
	}
}

func (c *Client) handleCommand(
	reader *bufio.Reader,
	input string,
) bool {
	parts := strings.Fields(input)

	if len(parts) == 0 {
		return false
	}

	switch parts[0] {
	case "help":
		c.printHelp()

	case "identity":
		fmt.Printf(
			"Identity: %s\n",
			identity.Address(c.Identity),
		)

	case "peers":
		c.printPeers()

	case "list":
		if len(parts) != 2 ||
			parts[1] != "messages" {
			fmt.Println(
				"Usage: list messages",
			)
			return false
		}

		c.listMessages()

	case "open":
		if len(parts) != 2 {
			fmt.Println(
				"Usage: open <message ID>",
			)
			return false
		}

		c.openMessage(parts[1])

	case "send":
		c.sendInteractive(reader)

	case "quit", "exit":
		return true

	default:
		fmt.Printf(
			"Unknown command %q. Type 'help'.\n",
			parts[0],
		)
	}

	return false
}

func (c *Client) printHelp() {
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  identity                 Show local identity")
	fmt.Println("  peers                    Show known peer identities")
	fmt.Println("  connect <host>:<port>    Connect to a peer")
	fmt.Println("  disconnect               Close current peer connection")
	fmt.Println("  list messages            List stored messages")
	fmt.Println("  open <message ID>        Open a stored message")
	fmt.Println("  send                     Send a message")
	fmt.Println("  help                     Show this help")
	fmt.Println("  quit                     Exit InkMail")
	fmt.Println()
}

// func (c *Client) connect(
// 	address string,
// ) error {
// 	c.closeSession()

// 	fmt.Printf(
// 		"Connecting to %s...\n",
// 		address,
// 	)

// 	session, err := network.Dial(
// 		address,
// 		c.Identity,
// 		c.Database,
// 	)
// 	if err != nil {
// 		return err
// 	}

// 	c.Session = session

// 	fmt.Printf(
// 		"Connected to %s::%s\n",
// 		session.PeerNamespace,
// 		identity.Fingerprint(session.Peer),
// 	)

// 	return nil
// }

func (c *Client) closeSession() {
	if c.Session == nil {
		return
	}

	_ = c.Session.Conn.Close()

	c.Session = nil

	fmt.Println(
		"Disconnected.",
	)
}

func (c *Client) listMessages() {
	messages, err := c.Database.ListMessages()
	if err != nil {
		fmt.Printf(
			"list messages: %v\n",
			err,
		)
		return
	}

	if len(messages) == 0 {
		fmt.Println(
			"No messages.",
		)
		return
	}

	fmt.Println()
	fmt.Printf(
		"%-64s  %-8s  %-24s  %s\n",
		"ID",
		"TYPE",
		"FROM",
		"SUBJECT",
	)

	for _, stored := range messages {
		from := fmt.Sprintf(
			"%s::%s",
			stored.Message.SenderNamespace,
			identity.FingerprintFromHex(
				stored.Message.SenderPublicKey,
			),
		)

		direction := stored.Direction

		fmt.Printf(
			"%-64s  %-8s  %-24s  %s\n",
			stored.Message.ID,
			direction,
			from,
			stored.Message.Subject,
		)
	}

	fmt.Println()
}

func (c *Client) openMessage(
	id string,
) {
	stored, err := c.Database.GetMessage(id)
	if err != nil {
		fmt.Printf(
			"open message: %v\n",
			err,
		)
		return
	}

	msg := stored.Message

	fmt.Println()
	fmt.Printf(
		"ID: %s\n",
		msg.ID,
	)
	fmt.Printf(
		"From: %s::%s\n",
		msg.SenderNamespace,
		identity.FingerprintFromHex(
			msg.SenderPublicKey,
		),
	)
	fmt.Printf(
		"To: %s::%s\n",
		msg.RecipientNamespace,
		identity.FingerprintFromHex(
			msg.RecipientPublicKey,
		),
	)
	fmt.Printf(
		"Subject: %s\n",
		msg.Subject,
	)
	fmt.Printf(
		"Date: %s\n",
		time.Unix(
			msg.CreatedAt,
			0,
		).Format("2006-01-02 15:04:05"),
	)
	fmt.Printf(
		"Status: %s\n",
		stored.Status,
	)
	fmt.Println()
	fmt.Println(msg.Body)
	fmt.Println()
}

func (c *Client) sendInteractive(
	reader *bufio.Reader,
) {
	// Get list of peers
	peers, err := c.Database.ListPeerIdentities()
	if err != nil {
		fmt.Printf(
			"list peers: %v\n",
			err,
		)
		return
	}

	if len(peers) == 0 {
		fmt.Println(
			"No known peers. Use 'peers' to see known identities.",
		)
		fmt.Println(
			"Import a peer with their identity information first.",
		)
		return
	}

	// Display peers with indexes
	fmt.Println()
	fmt.Println("Select recipient:")
	fmt.Println()

	for i, peer := range peers {
		fingerprint := hex.EncodeToString(peer.PublicKey[:8])
		fmt.Printf(
			"%d. %s::%s\n",
			i+1,
			peer.Namespace,
			fingerprint,
		)
	}

	fmt.Println()
	fmt.Print("Recipient (number or identity): ")

	selection, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	selection = strings.TrimSpace(selection)

	// Parse selection
	var selectedPeer *database.PeerIdentity
	var recipientNamespace string
	var recipientPublicKey []byte

	// Try to parse as number first
	if num, err := strconv.Atoi(selection); err == nil {
		if num < 1 || num > len(peers) {
			fmt.Println("Invalid selection.")
			return
		}
		selectedPeer = &peers[num-1]
		recipientNamespace = peers[num-1].Namespace
		recipientPublicKey = peers[num-1].PublicKey
	} else {
		// Try to parse as identity string
		// Format: namespace::fingerprint
		for i, peer := range peers {
			fingerprint := hex.EncodeToString(peer.PublicKey[:8])
			expectedIdentity := fmt.Sprintf(
				"%s::%s",
				peer.Namespace,
				fingerprint,
			)
			if strings.EqualFold(selection, expectedIdentity) {
				selectedPeer = &peers[i]
				recipientNamespace = peers[i].Namespace
				recipientPublicKey = peers[i].PublicKey
				break
			}
		}

		if selectedPeer == nil {
			// Try matching by namespace only (fuzzy match)
			for _, peer := range peers {
				if strings.EqualFold(selection, peer.Namespace) {
					selectedPeer = &peer
					recipientNamespace = peer.Namespace
					recipientPublicKey = peer.PublicKey
					break
				}
			}
		}

		if selectedPeer == nil {
			fmt.Println("Peer not found.")
			return
		}
	}

	if selectedPeer == nil {
		fmt.Println("No peer selected.")
		return
	}

	// Get message details
	fmt.Printf("\nSending to %s::%s\n",
		recipientNamespace,
		hex.EncodeToString(recipientPublicKey[:8]),
	)
	fmt.Println()

	fmt.Print("Subject: ")

	subject, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	subject = strings.TrimSpace(subject)

	if subject == "" {
		fmt.Println("Subject cannot be empty.")
		return
	}

	fmt.Println(
		"Enter message body. A single '.' on its own line sends the message.",
	)

	var body strings.Builder

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		line = strings.TrimSuffix(line, "\n")
		line = strings.TrimSuffix(line, "\r")

		if line == "." {
			break
		}

		body.WriteString(line)
		body.WriteByte('\n')
	}

	// Create and send the message using ghost networking
	fmt.Println()
	fmt.Println("Sending message...")
	fmt.Println()

	if err := c.sendMessageToPeer(
		recipientNamespace,
		recipientPublicKey,
		subject,
		body.String(),
	); err != nil {
		fmt.Printf("Send failed: %v\n", err)
		fmt.Println()
		return
	}

	fmt.Println("Message sent successfully.")
	fmt.Println()
}

// sendMessageToPeer implements ghost networking:
// 1. Find route to peer
// 2. Dial peer (or Daddy if no direct route)
// 3. Handshake (authenticate and exchange encryption keys)
// 4. Send encrypted message
// 5. Wait for ACK
// 6. Close connection
func (c *Client) sendMessageToPeer(
	recipientNamespace string,
	recipientPublicKey []byte,
	subject string,
	body string,
) error {
	// Create the message
	msg, err := message.New(
		c.Identity,
		recipientNamespace,
		recipientPublicKey,
		subject,
		body,
	)
	if err != nil {
		return fmt.Errorf("create message: %w", err)
	}

	fmt.Printf("Message ID: %s\n", msg.ID)
	fmt.Println()

	// Attempt to send via ghost connection
	// This will try direct connection first, then Daddy if needed
	addr, err := network.ResolveAndSend(
		c.Identity,
		c.Database,
		recipientNamespace,
		recipientPublicKey,
		msg,
	)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	if addr != nil {
		fmt.Printf("Delivered via: %s\n", addr.Address)
	} else {
		fmt.Println("Message held for delivery (recipient offline).")
	}

	return nil
}

func (c *Client) printPeers() {
	peers, err := c.Database.ListPeerIdentities()
	if err != nil {
		fmt.Printf(
			"list peers: %v\n",
			err,
		)
		return
	}

	if len(peers) == 0 {
		fmt.Println()
		fmt.Println("No known peers.")
		fmt.Println()
		fmt.Println(
			"Use 'invite <address>' to exchange identities with another InkMail node.",
		)
		fmt.Println()
		return
	}

	fmt.Println()
	fmt.Println("Known peers:")
	fmt.Println()

	for i, peer := range peers {
		fingerprint := identity.FingerprintFromHex(
			hex.EncodeToString(peer.PublicKey),
		)
		fmt.Printf(
			"%d. %s::%s\n",
			i+1,
			peer.Namespace,
			fingerprint,
		)
	}

	fmt.Println()
	fmt.Printf(
		"%d peer(s)\n",
		len(peers),
	)
	fmt.Println()
}
