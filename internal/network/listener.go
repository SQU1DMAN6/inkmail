package network

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/resource"
)

func Listen(
	port int,
	local *identity.Identity,
	db *database.Database,
) error {
	return ListenOn("0.0.0.0", port, local, db)
}

func ListenOn(
	host string,
	port int,
	local *identity.Identity,
	db *database.Database,
) error {
	address := net.JoinHostPort(strings.Trim(host, "[]"), fmt.Sprintf("%d", port))

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

	actualPort := port
	if tcpAddress, ok := listener.Addr().(*net.TCPAddr); ok {
		actualPort = tcpAddress.Port
	}
	if err := db.SetMeta(
		"listen_port",
		fmt.Sprintf("%d", actualPort),
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

	return serveListener(listener, local, db)
}

func serveListener(listener net.Listener, local *identity.Identity, db *database.Database) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
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
			runtimeStats.rejectedConnections.Add(1)
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

const (
	maxTrackedIdentities = 4096
)

type connectionLimiter struct {
	sync.Mutex
	active map[string]int
	global int
}

var inboundConnections = connectionLimiter{active: make(map[string]int)}
var resourceLimits = resource.Defaults()
var handshakeSlots = make(chan struct{}, resourceLimits.ConcurrentHandshakes)
var inFlightRequests = requestAdmission{active: make(map[string]int)}

type requestAdmission struct {
	sync.Mutex
	active map[string]int
	global int
}

func (admission *requestAdmission) acquire(identity string) bool {
	if identity == "" {
		identity = "unknown"
	}
	admission.Lock()
	defer admission.Unlock()
	if admission.global >= resourceLimits.ConcurrentRequests ||
		admission.active[identity] >= resourceLimits.ConcurrentRequestsPerIdentity {
		return false
	}
	admission.global++
	admission.active[identity]++
	return true
}

func (admission *requestAdmission) release(identity string) {
	if identity == "" {
		identity = "unknown"
	}
	admission.Lock()
	defer admission.Unlock()
	admission.global--
	admission.active[identity]--
	if admission.active[identity] <= 0 {
		delete(admission.active, identity)
	}
}

func (admission *requestAdmission) count() int {
	admission.Lock()
	defer admission.Unlock()
	return admission.global
}

type requestBucket struct {
	tokens   float64
	updated  time.Time
	lastSeen time.Time
}

type requestLimiter struct {
	sync.Mutex
	buckets map[string]requestBucket
}

var requestRateLimiter = requestLimiter{buckets: make(map[string]requestBucket)}
var handshakeFailureLimiter = handshakeLimiter{sources: make(map[string]handshakeFailureState)}

type handshakeFailureState struct {
	failures     int
	windowStart  time.Time
	blockedUntil time.Time
	lastSeen     time.Time
}

type handshakeLimiter struct {
	sync.Mutex
	sources map[string]handshakeFailureState
}

func (limiter *handshakeLimiter) allow(source string, now time.Time) bool {
	limiter.Lock()
	defer limiter.Unlock()
	state, exists := limiter.sources[source]
	if !exists {
		return true
	}
	state.lastSeen = now
	if now.Before(state.blockedUntil) {
		limiter.sources[source] = state
		return false
	}
	if now.Sub(state.windowStart) >= time.Duration(resourceLimits.HandshakeFailureWindowSeconds)*time.Second {
		delete(limiter.sources, source)
		return true
	}
	limiter.sources[source] = state
	return true
}

func (limiter *handshakeLimiter) failed(source string, now time.Time) {
	limiter.Lock()
	defer limiter.Unlock()
	state, exists := limiter.sources[source]
	if !exists || now.Sub(state.windowStart) >= time.Duration(resourceLimits.HandshakeFailureWindowSeconds)*time.Second {
		state = handshakeFailureState{windowStart: now}
	}
	state.failures++
	state.lastSeen = now
	if state.failures >= resourceLimits.HandshakeFailuresPerWindow {
		state.blockedUntil = now.Add(time.Duration(resourceLimits.HandshakeCooldownSeconds) * time.Second)
	}
	if len(limiter.sources) >= maxTrackedIdentities && !exists {
		limiter.evictOldest()
	}
	limiter.sources[source] = state
}

func (limiter *handshakeLimiter) succeeded(source string) {
	limiter.Lock()
	delete(limiter.sources, source)
	limiter.Unlock()
}

func (limiter *handshakeLimiter) evictOldest() {
	var oldestSource string
	var oldestSeen time.Time
	for source, state := range limiter.sources {
		if oldestSource == "" || state.lastSeen.Before(oldestSeen) {
			oldestSource = source
			oldestSeen = state.lastSeen
		}
	}
	delete(limiter.sources, oldestSource)
}

func (limiter *requestLimiter) allow(identity string, now time.Time) bool {
	return limiter.allowWithLimits(identity, now, resourceLimits)
}

func (limiter *requestLimiter) allowWithLimits(identity string, now time.Time, limits resource.Limits) bool {
	if identity == "" {
		identity = "unknown"
	}

	limiter.Lock()
	defer limiter.Unlock()

	capacity := float64(limits.RequestBurst)
	requestsPerMinute := float64(limits.RequestsPerMinute)
	if strings.HasPrefix(identity, "source:") {
		capacity *= 4
		requestsPerMinute *= 4
	}
	bucket, exists := limiter.buckets[identity]
	if !exists {
		if len(limiter.buckets) >= maxTrackedIdentities {
			limiter.evictOldest()
		}
		bucket = requestBucket{tokens: capacity, updated: now}
	}

	elapsed := now.Sub(bucket.updated).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * requestsPerMinute / 60
		if bucket.tokens > capacity {
			bucket.tokens = capacity
		}
	}
	bucket.updated = now
	bucket.lastSeen = now
	if bucket.tokens < 1 {
		limiter.buckets[identity] = bucket
		return false
	}
	bucket.tokens--
	limiter.buckets[identity] = bucket
	return true
}

func (limiter *requestLimiter) evictOldest() {
	var oldestIdentity string
	var oldestSeen time.Time
	for identity, bucket := range limiter.buckets {
		if oldestIdentity == "" || bucket.lastSeen.Before(oldestSeen) {
			oldestIdentity = identity
			oldestSeen = bucket.lastSeen
		}
	}
	delete(limiter.buckets, oldestIdentity)
}

func (limiter *connectionLimiter) acquire(address net.Addr) bool {
	key := sourceAddressKey(address)
	limiter.Lock()
	defer limiter.Unlock()
	if limiter.global >= resourceLimits.ConnectionsGlobal || limiter.active[key] >= resourceLimits.ConnectionsPerSource {
		return false
	}
	limiter.active[key]++
	limiter.global++
	return true
}

func ConfigureResourceLimits(limits resource.Limits) error {
	if err := limits.Validate(); err != nil {
		return err
	}
	inboundConnections.Lock()
	defer inboundConnections.Unlock()
	if inboundConnections.global != 0 {
		return fmt.Errorf("cannot change resource limits while connections are active")
	}
	inFlightRequests.Lock()
	defer inFlightRequests.Unlock()
	if inFlightRequests.global != 0 {
		return fmt.Errorf("cannot change resource limits while requests are active")
	}
	resourceLimits = limits
	handshakeSlots = make(chan struct{}, limits.ConcurrentHandshakes)
	inFlightRequests.active = make(map[string]int)
	inFlightRequests.global = 0
	requestRateLimiter.Lock()
	requestRateLimiter.buckets = make(map[string]requestBucket)
	requestRateLimiter.Unlock()
	return nil
}

func (limiter *connectionLimiter) release(address net.Addr) {
	key := sourceAddressKey(address)
	limiter.Lock()
	defer limiter.Unlock()
	limiter.active[key]--
	limiter.global--
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
