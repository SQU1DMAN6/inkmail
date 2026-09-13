package network

import (
	"context"
	"fmt"
	"net"
	"time"

	nattraversal "github.com/go-i2p/go-nat-listener"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
)

const (
	natDiscoveryTimeout = 15 * time.Second
)

func Listen(
	port int,
	local *identity.Identity,
	db *database.Database,
) error {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		natDiscoveryTimeout,
	)
	defer cancel()

	fmt.Printf(
		"Opening InkMail TCP port %d...\n",
		port,
	)

	listener, err := nattraversal.ListenWithFallbackContext(
		ctx,
		port,
	)
	if err != nil {
		return fmt.Errorf(
			"create network listener: %w",
			err,
		)
	}

	defer listener.Close()

	natAddress := listener.Addr().String()

	if listener.IsFallback() {
		fmt.Printf(
			"Automatic port forwarding unavailable.\n",
		)

		fmt.Printf(
			"InkMail is listening locally on %s\n",
			natAddress,
		)

		fmt.Printf(
			"Direct Internet connections may be unavailable.\n",
		)
	} else {
		fmt.Printf(
			"Automatic port forwarding enabled.\n",
		)

		fmt.Printf(
			"InkMail public address: %s\n",
			natAddress,
		)

		fmt.Printf(
			"External TCP port: %d\n",
			listener.ExternalPort(),
		)
	}

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
		"public_address",
		natAddress,
	); err != nil {
		return fmt.Errorf(
			"store public address: %w",
			err,
		)
	}

	if err := db.SetMeta(
		"nat_traversal",
		boolString(!listener.IsFallback()),
	); err != nil {
		return fmt.Errorf(
			"store NAT status: %w",
			err,
		)
	}

	fmt.Printf(
		"InkMail identity: qchef::%s.ed25519\n",
		identity.Fingerprint(local.PublicKey),
	)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if isTemporaryAcceptError(err) {
				fmt.Printf(
					"InkMail accept error: %v\n",
					err,
				)
				continue
			}

			return fmt.Errorf(
				"accept connection: %w",
				err,
			)
		}

		go func(conn net.Conn) {
			remote := conn.RemoteAddr().String()

			if err := HandleConnection(
				conn,
				local,
				db,
			); err != nil {
				fmt.Printf(
					"session from %s ended: %v\n",
					remote,
					err,
				)
				return
			}

			fmt.Printf(
				"session from %s closed\n",
				remote,
			)
		}(conn)
	}
}

func isTemporaryAcceptError(
	err error,
) bool {
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary()
	}

	return false
}

func boolString(value bool) string {
	if value {
		return "true"
	}

	return "false"
}
