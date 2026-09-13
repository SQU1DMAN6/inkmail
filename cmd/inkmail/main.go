package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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

	connectAddress := flag.String(
		"connect",
		"",
		"connect to an InkMail peer when the client starts",
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
		Session:  nil,
	}

	if *connectAddress != "" {
		if err := client.connect(
			*connectAddress,
		); err != nil {
			fmt.Printf(
				"connect: %v\n",
				err,
			)
		}
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

	case "connect":
		if len(parts) != 2 {
			fmt.Println(
				"Usage: connect <host>:<port>",
			)
			return false
		}

		if err := c.connect(
			parts[1],
		); err != nil {
			fmt.Printf(
				"connect: %v\n",
				err,
			)
		}

	case "disconnect":
		c.closeSession()

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

func (c *Client) connect(
	address string,
) error {
	c.closeSession()

	fmt.Printf(
		"Connecting to %s...\n",
		address,
	)

	session, err := network.Dial(
		address,
		c.Identity,
		c.Database,
	)
	if err != nil {
		return err
	}

	c.Session = session

	fmt.Printf(
		"Connected to %s::%s\n",
		session.PeerNamespace,
		identity.Fingerprint(session.Peer),
	)

	return nil
}

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
	if c.Session == nil {
		fmt.Println(
			"No peer connection. Use 'connect <host>:<port>' first.",
		)
		return
	}

	recipient := fmt.Sprintf(
		"%s::%s",
		c.Session.PeerNamespace,
		identity.Fingerprint(c.Session.Peer),
	)

	fmt.Printf(
		"Sending to %s\n",
		recipient,
	)

	fmt.Print("Subject: ")

	subject, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	subject = strings.TrimSpace(subject)

	if subject == "" {
		fmt.Println(
			"Subject cannot be empty.",
		)
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

		line = strings.TrimSuffix(
			line,
			"\n",
		)
		line = strings.TrimSuffix(
			line,
			"\r",
		)

		if line == "." {
			break
		}

		body.WriteString(line)
		body.WriteByte('\n')
	}

	msg, err := message.New(
		c.Identity,
		c.Session.PeerNamespace,
		c.Session.Peer,
		subject,
		body.String(),
	)
	if err != nil {
		fmt.Printf(
			"create message: %v\n",
			err,
		)
		return
	}

	fmt.Printf(
		"Message ID: %s\n",
		msg.ID,
	)

	if err := network.SendMessage(
		c.Session,
		c.Database,
		msg,
	); err != nil {
		fmt.Printf(
			"send message: %v\n",
			err,
		)
		return
	}

	fmt.Println(
		"Message delivered and acknowledged.",
	)
}

func (c *Client) printPeers() {
	fmt.Println(
		"Known peers are stored by identity, not network address.",
	)
	fmt.Println(
		"Peer listing is not implemented as a database query yet.",
	)
}
