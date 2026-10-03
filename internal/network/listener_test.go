package network

import (
	"fmt"
	"testing"
	"time"

	"github.com/SQU1DMAN6/inkmail/internal/resource"
)

type limiterTestAddr string

func (address limiterTestAddr) Network() string { return "test" }
func (address limiterTestAddr) String() string  { return string(address) }

func TestConnectionLimiterEnforcesSourceAndGlobalCaps(t *testing.T) {
	limiter := connectionLimiter{active: make(map[string]int)}
	for index := 0; index < resource.Defaults().ConnectionsPerSource; index++ {
		if !limiter.acquire(limiterTestAddr("shared-source")) {
			t.Fatalf("connection %d unexpectedly rejected", index+1)
		}
	}
	if limiter.acquire(limiterTestAddr("shared-source")) {
		t.Fatal("connection above per-source cap was admitted")
	}
	for index := 0; index < resource.Defaults().ConnectionsPerSource; index++ {
		limiter.release(limiterTestAddr("shared-source"))
	}

	for index := 0; index < resource.Defaults().ConnectionsGlobal; index++ {
		if !limiter.acquire(limiterTestAddr(fmt.Sprintf("source-%d", index))) {
			t.Fatalf("global connection %d unexpectedly rejected", index+1)
		}
	}
	if limiter.acquire(limiterTestAddr("overflow-source")) {
		t.Fatal("connection above global cap was admitted")
	}
	if limiter.global != resource.Defaults().ConnectionsGlobal {
		t.Fatalf("active global connections = %d, want %d", limiter.global, resource.Defaults().ConnectionsGlobal)
	}
}

func TestRequestLimiterThrottlesAndBoundsIdentityState(t *testing.T) {
	limiter := requestLimiter{buckets: make(map[string]requestBucket)}
	now := time.Unix(1000, 0)
	for request := 0; request < resource.Defaults().RequestBurst; request++ {
		if !limiter.allow("authenticated-user", now) {
			t.Fatalf("request %d unexpectedly throttled", request+1)
		}
	}
	if limiter.allow("authenticated-user", now) {
		t.Fatal("request above burst budget was admitted")
	}
	if !limiter.allow("authenticated-user", now.Add(200*time.Millisecond)) {
		t.Fatal("request after token refill was throttled")
	}

	for index := 0; index < maxTrackedIdentities+10; index++ {
		if !limiter.allow(fmt.Sprintf("identity-%d", index), now) {
			t.Fatalf("first request for identity %d unexpectedly throttled", index)
		}
	}
	if len(limiter.buckets) > maxTrackedIdentities {
		t.Fatalf("tracked identities = %d, exceeds cap %d", len(limiter.buckets), maxTrackedIdentities)
	}
}

func TestHandshakeLimiterThrottlesRepeatedFailures(t *testing.T) {
	limiter := handshakeLimiter{sources: make(map[string]handshakeFailureState)}
	now := time.Unix(2000, 0)
	for attempt := 0; attempt < resource.Defaults().HandshakeFailuresPerWindow; attempt++ {
		if !limiter.allow("source", now) {
			t.Fatalf("handshake attempt %d unexpectedly throttled", attempt+1)
		}
		limiter.failed("source", now)
	}
	if limiter.allow("source", now) {
		t.Fatal("source was not throttled after repeated failures")
	}
	cooldown := time.Duration(resource.Defaults().HandshakeCooldownSeconds) * time.Second
	if !limiter.allow("source", now.Add(cooldown)) {
		t.Fatal("source remained throttled after cooldown")
	}
	limiter.succeeded("source")
	if len(limiter.sources) != 0 {
		t.Fatalf("successful handshake did not clear failure state: %d entries", len(limiter.sources))
	}
}

func TestHandshakeLimiterBoundsSourceState(t *testing.T) {
	limiter := handshakeLimiter{sources: make(map[string]handshakeFailureState)}
	now := time.Unix(3000, 0)
	for index := 0; index < maxTrackedIdentities+10; index++ {
		limiter.failed(fmt.Sprintf("source-%d", index), now)
	}
	if len(limiter.sources) > maxTrackedIdentities {
		t.Fatalf("tracked handshake sources = %d, exceeds cap %d", len(limiter.sources), maxTrackedIdentities)
	}
}
