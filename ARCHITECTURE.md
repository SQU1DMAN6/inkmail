# InkMail architecture

InkMail is built around a small set of layered components that separate local identity management, durable state, encrypted message handling, and network delivery.

This document explains how the architecture works in practice and why the design is strong for privacy-focused messaging.

## High-level structure

The codebase is organized into a few major areas:

- `cmd/inkmail/` — the interactive user CLI
- `cmd/inkmaild/` — the background daemon/listener
- `internal/identity/` — identity generation and validation
- `internal/database/` — SQLite-backed local state, contacts, and opaque relay mailbox storage
- `internal/message/` — message signing, encryption, and opaque mailbox envelopes
- `internal/network/` — direct and relay-based transport, route registration, delivery flow, and mailbox-sync logic

The CLI and daemon share the same identity and storage logic, but they are intentionally separated so the user can interact with the mail client while the daemon keeps the network side available in the background.

## 1. Identity and key model

The identity layer is defined in `internal/identity/identity.go`.

### What it stores

Each local node gets:

- an Ed25519 private/public keypair for identity and signature verification,
- an X25519 keypair for end-to-end message encryption,
- a namespace string used as a logical account scope.

The code generates these keys on first launch and stores them securely on disk using strict file permissions (`0600` for private keys, `0644` for public material). SQLite separately creates a random 256-bit mailbox ID shared as part of a contact bundle; it is not derived from either keypair.

### Why this is effective

The design clearly separates:

- identity ownership from message encryption,
- long-term authentication from transport encryption,
- direct recipient validation from message body confidentiality.

The Ed25519 identity proves the sender is who they claim to be. The X25519 pair is used for message encryption so that only the legitimate recipient can decrypt the subject and body.

### Security benefit

This means that relays and Daddy nodes do not need private signing keys or
decryption keys to operate. The Daddy-facing wire envelope wraps the existing
signed end-to-end encrypted envelope in a second X25519/ChaCha20-Poly1305 layer.
Its outer fields are a random mailbox ID, random envelope ID, ephemeral key,
nonce, and padded ciphertext. Sender/recipient cryptographic identities and
user-visible message metadata are inside that encrypted payload.

## 2. Local SQLite database

The database layer in `internal/database/` stores the durable user state:

- peer identities and aliases,
- route records and expiration timestamps,
- encrypted or decrypted message records,
- opaque encrypted envelopes waiting for pickup,
- local mailbox folders and an encrypted-envelope outbox,
- local metadata such as sync watermarks and listening port state.

The database initializes with SQLite WAL mode and foreign-key enforcement, which helps keep writes atomic and local state easier to recover in the event of a crash.

### Why this is effective

The project treats the local SQLite store as the source of truth for user-visible state. Messages are stored locally before and during send attempts so the client remains resilient even if routes fail or a relay is temporarily unavailable.

This is visible in the CLI: `sendMessageToPeer` writes the message into the local database before attempting any network transfer.

### Consideration

This model is effective for a desktop or personal host, but a production deployment should still guard the SQLite file and key directory with strong OS file permissions, backups, and secure host configuration.

## 3. Message signing and end-to-end encryption

The message model is in `internal/message/message.go` and `internal/message/mailboxop.go`.

### Message signing

A message is signed with Ed25519 over canonical fields including:

- sender namespace,
- sender public key,
- recipient namespace,
- recipient public key,
- subject,
- body,
- creation timestamp.

The resulting message ID is derived from those values, and the code verifies it before accepting the message as valid.

### End-to-end encryption

The subject and body are encrypted with ChaCha20-Poly1305 after deriving a symmetric key from an ephemeral X25519 key agreement. The sender generates an ephemeral key, derives a shared secret with the recipient’s public encryption key, and uses the resulting key material to encrypt the plaintext.

The encrypted envelope includes:

- sender identity,
- recipient identity,
- recipient encryption key,
- ephemeral public key,
- nonce,
- ciphertext,
- signature.

### Why this is effective

Relays never need to inspect plaintext. They only carry the encrypted message and routing metadata. The recipient is the only node that can derive the decryption key with its own X25519 private key.

The project also verifies signatures before decryption. In other words, it refuses to decrypt unauthenticated or malformed content.

### Security benefit

This is the core confidentiality boundary: a relay or Daddy can observe that a message exists, who it is addressed to, and some metadata, but not the actual message body.

## 4. Transport layer and ghost networking

The network layer in `internal/network/` is the heart of message delivery.

### Handshake

The handshake is implemented in `handshake.go`.

Each side sends a signed HELLO message containing:

- protocol version,
- namespace,
- Ed25519 public key,
- X25519 encryption key,
- ephemeral X25519 key,
- timestamp,
- signature.

The system then performs X25519 ECDH between the two ephemeral keys and derives directional session keys using HKDF and a domain-specific transcript.

### Session encryption

After authentication, each side derives distinct send/receive keys for the temporary transport connection. These keys are never persisted beyond session lifetime.

### Why this is effective

The long-term identity key is not used for transport encryption. That keeps the authentication key separate from the ephemeral session keys and reduces the impact of a session compromise.

This is a good pattern because it prevents transport-key reuse and keeps the session isolated to a single brief exchange.

## 5. Route registration and routing

The network layer supports route registration and lookup through Daddy or direct peers.

- `REGISTER_ROUTE` stores a temporary address that a node claims to own.
- `LOOKUP_ROUTE` resolves an opaque mailbox ID to an active route.
- The route includes expiration metadata, and route registration is capped by a max lifetime.

The code does not allow an unlimited route or a permanent point of contact. The route TTL is deliberately short, which reduces stale routes and helps the network converge.

### Why this is effective

The route is keyed by a high-entropy mailbox bearer ID. Daddy-facing handshakes
use a random one-session relay identity, and route requests contain no namespace
or public key. Daddy still learns the advertised address associated with that
mailbox ID while the route is active.

## 6. Direct delivery, relay fallback, and hold-and-forward

InkMail chooses delivery strategy based on available route information.

### Direct delivery

If a route is known and reachable, the sender dials the recipient directly and delivers an encrypted envelope over a temporary session.

### Relay/Daddy fallback

If a route is unavailable, the sender hands a padded opaque mailbox envelope to
Daddy. Daddy indexes it by mailbox ID, stores only ciphertext temporarily, and
returns it when that mailbox polls.

The protocol supports a hold-and-forward model and a direct message flow, and it distinguishes “accepted responsibility” from “fully delivered.”

### Why this is effective

This makes the network resilient to partial connectivity, NAT, and transient relays. It prioritizes delivery while avoiding reliance on a single always-online host.

### Considerations

This architecture still assumes the relay network is reachable and that the user configures valid endpoints. If a relay is malicious or misconfigured, it can still observe metadata such as routing or timing. The code does not conceal the existence of a message from a relay; it only hides the contents.

## 7. Local mailbox and delivery receipts

`msg mv` updates only the local `messages.folder` field. `msg del` deletes the
local message row, securely erases freed SQLite pages, and checkpoints the WAL.
Neither operation contacts Daddy or creates a synchronization record. Moving a
message into the local `deleted` folder is separate from hard deletion.

Outgoing messages move from `queued` to `pending` after Daddy accepts the
envelope. After a recipient verifies and saves an incoming message, it sends a
recipient-signed receipt as another opaque encrypted mailbox envelope addressed
to the sender's mailbox ID. Each Daddy immediately removes a held envelope
after its delivery ACK. The receipt is held only as an active encrypted
envelope until the sender fetches and acknowledges it; the sender verifies its
signed inner message and changes the matching outgoing item to `delivered`.

## 8. Implemented protections and limits

Daddy persists opaque mailbox routes and active ciphertext rows. A held row
contains only a mailbox ID, random envelope ID, ciphertext, and expiry. Message
identities, public keys, plaintext, subject, inner message ID, and local folder
operations are encrypted or remain only on the user's device. The encrypted
payload is padded to 64 KiB plaintext size classes.

Mailbox IDs are stable random bearer tokens, so Daddy can link multiple
envelopes to the same opaque mailbox. Daddy can also observe advertised route
addresses, transport source addresses, timing, and approximate padded sizes.
Direct peers still authenticate one another by cryptographic identity. These
changes do not provide Tor-like anonymity or traffic-analysis resistance.

Protocol v4 binds anonymous-session status into the signed handshake; earlier
protocol versions fail negotiation clearly. Database upgrades keep legacy
relay tables and route rows instead of dropping or clearing them. Existing
`~/.inkmail` data therefore needs no manual cleanup; legacy rows remain
preserved in place and are not reinterpreted as current opaque envelopes.

The 1.2 development daemon bounds inbound connections per source and globally,
concurrent handshakes and requests per identity, request rates by identity,
source, and mailbox, and failed handshake retries by source and hashed claimed
identity. Held-envelope counts and bytes are capped per submitter, per mailbox,
and globally; replay records, local outbox bytes/counts, mailbox ownership,
peer identities, and direct routes are capped as well. Expired mailbox and
direct routes are cleaned on the daemon cleanup cycle.

The optional JSON file passed through `inkmaild --resources` has safe defaults,
validated ranges, and hard ceilings. Fixed frame, handshake, individual
envelope, fetch-batch, and retention ceilings cannot be raised. Startup leaves
legacy tables and routes in place. Legacy relay table rows and stored-value
bytes count against the global held-storage quota; current admission does not
rewrite or activate those rows.

The daemon emits bounded operational counters once per minute. Local TCP
integration coverage is in `internal/network/resource_integration_test.go`;
database upgrade/quota cases are in `internal/database/mailbox_privacy_test.go`.
See `doc/BUILD-v1_2-REVIEW.md` for the combined-specification coverage ledger.

## 9. Daemon and CLI split

The project separates the user experience from the network service.

- `inkmail` is interactive and human-oriented.
- `inkmaild` runs as a background listener and keeps network connections alive.

The daemon opens a TCP listener, stores the listening port in the database, and runs persistent dial logic while waiting for inbound sessions.

### Why this is effective

This division is useful for local hosting and background operation. The CLI can remain occasional and user-driven, while the daemon maintains connectivity and mailbox availability.

## 10. Security properties of the design

This architecture is intentionally layered:

- The identity layer authenticates who a node is.
- The message layer makes contents private.
- The transport layer protects each connection.
- The route system limits exposure of the user’s real address.
- The mailbox layer enforces signed state transitions.

This is strongest when all of these are respected together.

### Benefits

- Private message contents are not visible to relays.
- Client identities are hard to spoof without the private Ed25519 key.
- Messages are not replayed or reinterpreted without signature verification.
- Stale routes expire and are replaced systematically.
- Local message state remains durable even when network delivery is intermittent.

### Potential considerations

- Node operators must protect the local identity directory.
- Active relays or Daddy servers can still see metadata and timing patterns.
- Deployment requires good port and firewall hygiene for inbound listeners.
- The code currently relies on network discovery and configured relays; it does not automatically solve all NAT/firewall problems on its own.
- The trust model is only as good as the configured relay operators and the operational security of the host.

## Summary

InkMail’s design is effective because it layers authentication, encryption, route validation, and durable local state. It does not attempt to hide everything from relays, but it does keep message contents confidential while still allowing the system to route and store messages reliably.

That makes it appropriate as a lightweight, privacy-aware mail client with a direct-message/relay-fallback model rather than a full centralized messaging platform.

The code reflects this philosophy across the entire project: identities are verified first, encrypted content is stored and relayed only in ciphertext, routes are ephemeral and authenticated, and the mailbox converges through signed operations.
