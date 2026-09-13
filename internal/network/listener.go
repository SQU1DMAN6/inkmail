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
    address := fmt.Sprintf("0.0.0.0:%d", port)

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

    listenAddress := listener.Addr().String()

    fmt.Printf(
        "InkMail listening on %s\n",
        listenAddress,
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
        "public_address",
        "",
    ); err != nil {
        return fmt.Errorf(
            "store public address: %w",
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
        "InkMail identity: qchef::%s.ed25519\n",
        identity.Fingerprint(local.PublicKey),
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
