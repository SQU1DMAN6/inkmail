package network

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"

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
			if isTemporaryAcceptError(err) {
				timer := time.NewTimer(100 * time.Millisecond)
				<-timer.C
				continue
			}
			return fmt.Errorf(
				"accept connection: %w",
				err,
			)
		}
		if !inboundConnections.acquire(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}

		go func(conn net.Conn) {
			defer inboundConnections.release(conn.RemoteAddr())
			_ = HandleConnection(
				conn,
				local,
				db,
			)
		}(conn)
	}
}

func isTemporaryAcceptError(err error) bool {
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Temporary()
}

const maxConnectionsPerSource = 8

type connectionLimiter struct {
	sync.Mutex
	active map[string]int
}

var inboundConnections = connectionLimiter{active: make(map[string]int)}

func (limiter *connectionLimiter) acquire(address net.Addr) bool {
	key := sourceAddressKey(address)
	limiter.Lock()
	defer limiter.Unlock()
	if limiter.active[key] >= maxConnectionsPerSource {
		return false
	}
	limiter.active[key]++
	return true
}

func (limiter *connectionLimiter) release(address net.Addr) {
	key := sourceAddressKey(address)
	limiter.Lock()
	defer limiter.Unlock()
	limiter.active[key]--
	if limiter.active[key] <= 0 {
		delete(limiter.active, key)
	}
}

func sourceAddressKey(address net.Addr) string {
	if address == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(address.String())
	if err == nil {
		return host
	}
	return address.String()
}
