package network

import (
	"fmt"
	"net"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

func Listen(
	port int,
	local *identity.Identity,
	db *database.Database,
) error {
	address := fmt.Sprintf(
		"0.0.0.0:%d",
		port,
	)

	fmt.Printf(
		"Opening InkMail TCP port %d...\n",
		port,
	)

	listener, err := net.Listen(
		"tcp",
		address,
	)
	if err != nil {
		return fmt.Errorf(
			"listen on %s: %w",
			address,
			err,
		)
	}

	defer listener.Close()

	fmt.Printf(
		"InkMail listening on %s\n",
		listener.Addr().String(),
	)

	if err := db.SetMeta(
		"listen_port",
		fmt.Sprintf("%d", port),
	); err != nil {
		return fmt.Errorf(
			"store listen port: %w",
			err,
		)
	}

	if err := db.SetMeta(
		"nat_traversal",
		"false",
	); err != nil {
		return fmt.Errorf(
			"store NAT status: %w",
			err,
		)
	}

	fmt.Printf(
		"InkMail identity: %s\n",
		identity.Address(local),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf(
				"accept connection: %w",
				err,
			)
		}

		go func(conn net.Conn) {
			if err := HandleConnection(
				conn,
				local,
				db,
			); err != nil {
				fmt.Printf(
					"connection rejected: %v\n",
					err,
				)
				return
			}

			fmt.Println(
				"authenticated session closed",
			)
		}(conn)
	}
}
