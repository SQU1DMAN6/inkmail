package network

import (
	"fmt"
	"net"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

func Listen(
	address string,
	local *identity.Identity,
	db *database.Database,
) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", address, err)
	}

	defer listener.Close()

	fmt.Printf("InkMail listening on %s\n", listener.Addr())
	fmt.Printf(
		"InkMail identity: qchef::%s.ed25519\n",
		identity.Fingerprint(local.PublicKey),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("accept error: %v\n", err)
			continue
		}

		go func() {
			if err := HandleConnection(conn, local, db); err != nil {
				fmt.Printf(
					"connection from %s failed: %v\n",
					conn.RemoteAddr(),
					err,
				)
			}
		}()
	}
}
