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
	fmt.Println("▗▄▄▄▖     ▗▄▄▖       ▄▄▄      ▗▖   ▗▄ ▄▖       █  ▗▄▖")
	fmt.Println("▐▛▀▀▘ ▐▌  ▐▛▀▜▌      ▀█▀      ▐▌   ▐█ █▌       ▀  ▝▜▌")
	fmt.Println("▐▌   ▐███ ▐▌ ▐▌       █  ▐▙██▖▐▌▟▛ ▐███▌ ▟██▖ ██   ▐▌")
	fmt.Println("▐███  ▐▌  ▐███        █  ▐▛ ▐▌▐▙█  ▐▌█▐▌ ▘▄▟▌  █   ▐▌")
	fmt.Println("▐▌    ▐▌  ▐▌▝█▖       █  ▐▌ ▐▌▐▛█▖ ▐▌▀▐▌▗█▀▜▌  █   ▐▌")
	fmt.Println("▐▌    ▐▙▄ ▐▌ ▐▌      ▄█▄ ▐▌ ▐▌▐▌▝▙ ▐▌ ▐▌▐▙▄█▌▗▄█▄▖ ▐▙▄")
	fmt.Println("▝▘     ▀▀ ▝▘ ▝▀      ▀▀▀ ▝▘ ▝▘▝▘ ▀▘▝▘ ▝▘ ▀▀▝▘▝▀▀▀▘  ▀▀")
	fmt.Println("======================================================")
	fmt.Println("Welcome to the InkMail Client")
	fmt.Println("InkMail 1.0, written by Quan Thai")
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
			"Identity: %s\nFull identity: %s\n",
			identity.Address(c.Identity),
			identity.AddressFull(c.Identity),
		)

	case "peers":
		c.handlePeersCommand(parts[1:])

	case "msg":
		c.handleMsgCommand(parts[1:])

	case "relays":
		if len(parts) > 1 && parts[1] == "probe" {
			c.probeRelays()
		} else {
			c.printRelays()
		}

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
	fmt.Println("  peers [list]             List peers, aliases, status, and reachability")
	fmt.Println("  peers add <Peer ID>      Register a peer using full identity key")
	fmt.Println("  peers remove <number>    Remove a peer entry, alias and cached routes")
	fmt.Println("  peers alias <n> <alias>  Set friendly alias for peer")
	fmt.Println("  relays                   Show configured Daddy relays")
	fmt.Println("  relays probe             Measure relay latency")
	fmt.Println("  msg [folder]             List inbox (or folder: archive, important, all)")
	fmt.Println("  msg mv <ID> <folder>     Move a message")
	fmt.Println("  msg del <ID>             Delete a message")
	fmt.Println("  msg sync                 Pull signed mailbox operations from Daddy")
	fmt.Println("  open <ID>                Open a stored message")
	fmt.Println("  send                     Send a message")
	fmt.Println("  help                     Show this help message")
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

func (c *Client) listMessagesIn(folder string) {
	name := strings.ToLower(strings.TrimSpace(folder))
	if name == "" {
		name = database.FolderInbox
	}

	messages, err := c.Database.ListMessagesInFolder(name)
	if err != nil {
		fmt.Printf(
			"msg: %v\n",
			err,
		)
		return
	}

	if len(messages) == 0 {
		fmt.Printf(
			"No messages in %q.\n",
			name,
		)
		return
	}

	fmt.Printf("\nFolder: %s\n\n", name)
	fmt.Printf(
		"%-64s  %-8s  %-24s  %s\n",
		"ID",
		"TYPE",
		"FROM",
		"SUBJECT",
	)

	for _, stored := range messages {
		direction := database.NormaliseDirection(stored.Direction)

		from := fmt.Sprintf(
			"%s::%s",
			stored.Message.SenderNamespace,
			identity.FingerprintFromHex(
				stored.Message.SenderPublicKey,
			),
		)

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

	if folder, err := c.Database.GetMessageFolder(id); err != nil {
		fmt.Printf("open message: %v\n", err)
		return
	} else if folder == database.FolderDeleted {
		fmt.Printf("open message: message %q is deleted\n", id)
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

// handleMsgCommand routes msg inbox/folder views and signed mutations.
func (c *Client) handleMsgCommand(args []string) {
	if len(args) == 0 {
		c.listMessagesIn(database.FolderInbox)
		return
	}

	switch strings.ToLower(args[0]) {
	case "sync":
		c.syncMailbox()
		return
	case "mv":
		if len(args) != 3 {
			fmt.Println("Usage: msg mv <message ID> <folder>")
			return
		}
		c.moveMessage(args[1], args[2])
		return
	case "del", "delete", "rm":
		if len(args) != 2 {
			fmt.Println("Usage: msg del <message ID>")
			return
		}
		c.deleteMessage(args[1])
		return
	}

	if len(args) == 1 {
		c.listMessagesIn(args[0])
		return
	}

	fmt.Println("Usage: msg [folder] | msg mv <ID> <folder> | msg del <ID> | msg sync")
}

// moveMessage signs a move op, applies it locally, then replicates to Daddy.
func (c *Client) moveMessage(id string, folder string) {
	target, err := database.NormaliseFolder(folder)
	if err != nil {
		fmt.Printf("msg mv: %v\n", err)
		return
	}

	stored, err := c.Database.GetMessage(strings.TrimSpace(id))
	if err != nil {
		fmt.Printf("msg mv: %v\n", err)
		return
	}

	op, err := message.SignMailboxOpForMessage(
		c.Identity.PrivateKey,
		c.Identity.Namespace,
		c.Identity.PublicKey,
		&stored.Message,
		message.MailboxOpMove,
		target,
		time.Now().Unix(),
	)
	if err != nil {
		fmt.Printf("msg mv: %v\n", err)
		return
	}

	if err := c.applySignedOp(op); err != nil {
		fmt.Printf("msg mv: %v\n", err)
		return
	}

	fmt.Printf("Moved %s to %q.\n", strings.TrimSpace(id), target)
}

// deleteMessage signs a delete tombstone, applies it, replicates to Daddy.
func (c *Client) deleteMessage(id string) {
	stored, err := c.Database.GetMessage(strings.TrimSpace(id))
	if err != nil {
		fmt.Printf("msg del: %v\n", err)
		return
	}

	op, err := message.SignMailboxOpForMessage(
		c.Identity.PrivateKey,
		c.Identity.Namespace,
		c.Identity.PublicKey,
		&stored.Message,
		message.MailboxOpDelete,
		"",
		time.Now().Unix(),
	)
	if err != nil {
		fmt.Printf("msg del: %v\n", err)
		return
	}

	if err := c.applySignedOp(op); err != nil {
		fmt.Printf("msg del: %v\n", err)
		return
	}

	fmt.Printf("Deleted %s.\n", strings.TrimSpace(id))
}

// applySignedOp verifies author-is-self, applies LWW state, broadcasts.
func (c *Client) applySignedOp(op *message.MailboxOpRequest) error {
	if err := op.Verify(); err != nil {
		return err
	}

	selfKey := hex.EncodeToString(c.Identity.PublicKey)

	if op.AuthorNS != c.Identity.Namespace ||
		!strings.EqualFold(op.AuthorKey, selfKey) {
		return fmt.Errorf("op author is not this device")
	}

	authorKey, err := hex.DecodeString(op.AuthorKey)
	if err != nil {
		return err
	}

	signature, err := hex.DecodeString(op.Signature)
	if err != nil {
		return err
	}

	senderKey, err := hex.DecodeString(op.SenderKey)
	if err != nil {
		return err
	}

	recipientKey, err := hex.DecodeString(op.RecipientKey)
	if err != nil {
		return err
	}

	if _, err := c.Database.ApplyMailboxOp(database.MailboxOp{
		MessageID:    op.MessageID,
		Op:           strings.ToLower(strings.TrimSpace(op.Op)),
		Folder:       strings.ToLower(strings.TrimSpace(op.Folder)),
		SenderNS:     op.SenderNS,
		SenderKey:    senderKey,
		RecipientNS:  op.RecipientNS,
		RecipientKey: recipientKey,
		AuthorNS:     op.AuthorNS,
		AuthorKey:    authorKey,
		Timestamp:    op.Timestamp,
		Signature:    signature,
	}); err != nil {
		return err
	}

	if err := network.BroadcastMailboxOp(c.Identity, c.Database, op); err != nil {
		fmt.Printf("Daddy sync deferred (%v); local state kept.\n", err)
	}

	c.syncMailboxQuiet()

	return nil
}

// syncMailbox pulls signed ops from all relays and applies verified state.
func (c *Client) syncMailbox() {
	since, err := c.mailboxWatermark()
	if err != nil {
		since = 0
	}

	next := network.SyncMailboxOpsAll(c.Identity, c.Database, since)

	if err := c.Database.SetMeta("mailbox_since", strconv.FormatInt(next, 10)); err != nil {
		fmt.Printf("msg sync: %v\n", err)
		return
	}

	fmt.Printf("Mailbox synced (%d -> %d).\n", since, next)
}

func (c *Client) syncMailboxQuiet() {
	since, err := c.mailboxWatermark()
	if err != nil {
		return
	}

	next := network.SyncMailboxOpsAll(c.Identity, c.Database, since)

	_ = c.Database.SetMeta("mailbox_since", strconv.FormatInt(next, 10))
}

func (c *Client) mailboxWatermark() (int64, error) {
	raw, err := c.Database.GetMeta("mailbox_since")
	if err != nil || strings.TrimSpace(raw) == "" {
		return 0, nil
	}

	return strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
}

func (c *Client) probeRelays() {
	results := network.ProbeRelaysAll(c.Identity, c.Database)

	fmt.Println()
	fmt.Println("Relay latency (ms, -1 = unreachable):")
	fmt.Println()

	for relay, ms := range results {
		fmt.Printf("  %-28s %d\n", relay, ms)
	}

	fmt.Println()
}

func (c *Client) printRelays() {
	addresses := network.DaddyAddresses(c.Database, "")

	fmt.Println()
	fmt.Println("Configured relays (dial order):")
	fmt.Println()

	for i, address := range addresses {
		fmt.Printf(
			"%d. %s\n",
			i+1,
			address,
		)
	}

	fmt.Println()
	fmt.Printf("%d relay(s)\n", len(addresses))
	fmt.Println()
	fmt.Println("Edit relays.conf in the data directory to change priority.")
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

	// Display peers with indexes + aliases
	fmt.Println()
	fmt.Println("Select recipient:")
	fmt.Println()

	for i, peer := range peers {
		fingerprint := hex.EncodeToString(peer.PublicKey[:8])
		label := fmt.Sprintf(
			"%d. %s::%s",
			i+1,
			peer.Namespace,
			fingerprint,
		)
		if peer.Alias != "" {
			label += fmt.Sprintf(" (%s)", peer.Alias)
		}
		fmt.Println(label)
	}

	fmt.Println()
	fmt.Print("Recipient (number, alias or identity): ")

	selection, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	selection = strings.TrimSpace(selection)

	// Parse selection via shared resolver (number -> alias -> identity).
	selectedPeer, err := c.resolveSendRecipient(selection, peers)
	if err != nil {
		fmt.Println(err.Error() + ".")
		return
	}

	recipientNamespace := selectedPeer.Namespace
	recipientPublicKey := selectedPeer.PublicKey

	confirmLabel := fmt.Sprintf(
		"%s::%s",
		recipientNamespace,
		hex.EncodeToString(recipientPublicKey[:8]),
	)
	if selectedPeer.Alias != "" {
		confirmLabel += fmt.Sprintf(" (%s)", selectedPeer.Alias)
	}
	fmt.Printf("\nSending to %s\n", confirmLabel)
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
// 1. Persist the message locally as queued (visible in `msg` immediately).
// 2. Find route to peer.
// 3. Dial peer directly or hand the envelope to Daddy.
// 4. Promote the local copy to sent once InkMail accepts responsibility.
// 5. Close every connection as soon as the exchange completes.
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

	// Persist the message locally BEFORE any network activity so the sender
	// always sees it in `msg`, even if every route is dead (SPEC v0.5
	// sections 4, 7, Test A).
	if err := c.Database.StoreMessage(
		msg,
		database.DirectionQueued,
		"queued",
	); err != nil {
		return fmt.Errorf("store local message: %w", err)
	}

	fmt.Println("Message queued.")
	fmt.Println()

	// Attempt to send via ghost connection.
	// This will try direct connection first, then Daddy if needed.
	result, err := network.ResolveAndSend(
		c.Identity,
		c.Database,
		recipientNamespace,
		recipientPublicKey,
		msg,
	)
	if err != nil {
		fmt.Println("Message queued for retry.")
		fmt.Println("Recipient has not yet confirmed receipt.")
		fmt.Println()
		return fmt.Errorf("send message: %w", err)
	}

	// InkMail has accepted responsibility: either the recipient ACKed the
	// envelope directly or Daddy replied HOLD_ACK. Either way the message is
	// `sent` from the sender's perspective. It is NOT `received` until the
	// destination stores it and returns DELIVERY_ACK (SPEC v0.5 sections 5,
	// 8, 11).
	//
	// A single StoreMessage promotion flips both direction and status, so the
	// row never lingers as direction=queued/status=sent.
	if err := c.Database.StoreMessage(
		msg,
		database.DirectionSent,
		"sent",
	); err != nil {
		return fmt.Errorf("mark message sent: %w", err)
	}

	if result != nil && result.Delivered {
		fmt.Println("Message delivered and acknowledged.")
	} else if result != nil && result.Relayed {
		fmt.Println("Message sent to Daddy and queued for delivery.")
		fmt.Println("Status: queued")
	} else {
		fmt.Println("Message accepted for delivery.")
	}

	fmt.Println("Recipient has not yet confirmed receipt.")
	fmt.Println()

	if result != nil && result.Address != "" {
		fmt.Printf("Delivered via: %s\n", result.Address)
	}

	return nil
}
