# FtR InkMail

**Current Release**: FtR InkMail 1.0.0, September 2026

## Things to read

1. [What InkMail does](#what-inkmail-does)
2. [First run](#first-run)
3. [Core commands](#core-commands)
4. [Relay status and probing](#relay-status-and-probing)
5. [Running the daemon](#running-the-daemon)
6. [Security and trust model](#security-and-trust-model)
7. [Practical usage notes](#practical-usage-notes)

InkMail is a privacy-oriented mail client for peer-to-peer messaging over a lightweight relay network. It stores a local identity, keeps a SQLite database on disk, and can send messages either directly to a known peer or through a configured Daddy/relay node when direct connectivity is unavailable.

This project is not a web app or a social network. It is a command-line mail client built around the idea that:

- each user has an Ed25519 identity key,
- each message is signed and then encrypted for the recipient,
- relays and Daddy nodes only see encrypted payloads and routing metadata,
- the local node keeps a durable mailbox and peer list.

The actual command-line interface is the `inkmail` client. A separate daemon, `inkmaild`, listens for incoming ghost-network traffic and keeps a persistent connection to configured relay endpoints.

## What InkMail does

InkMail maintains a local mailbox with a user identity, a peer directory, and a small database of route and message state. The supported flow is:

1. create or load a local identity,
2. add peers by full identity,
3. send a signed and encrypted message,
4. let the network attempt direct delivery first,
5. fall back to Daddy/relay hold-and-forward if direct delivery fails,
6. sync mailbox operations so move/delete state converges across devices.

The local database stores messages in folders such as `inbox`, `archive`, and `important`, plus a separate queue for outgoing items waiting for acknowledgement.

## First run

When you launch InkMail for the first time, it creates a data directory at `~/.inkmail` by default. Inside that directory it stores:

- `identity/` with your generated key material,
- `node.db` with the SQLite mailbox and peer metadata,
- `relays.conf` if you add one manually,
- local metadata such as relay preferences and mailbox sync checkpoints.

Start the client:

```bash
cd /path/to/inkmail
go build -o build/inkmail ./cmd/inkmail
./build/inkmail
```

You may also pass a custom data directory and user namespace:

```bash
./build/inkmail --data ~/.inkmail --user alice
```

On first launch, InkMail generates a private Ed25519 identity and a separate X25519 encryption keypair. It prints the identity address and then drops you into the REPL shell:

```text
inkmail>
```

The CLI is interactive, and the help text is available with:

```text
help
```

## Core commands

### Show your identity

```text
identity
```

This prints:

- your short identity address,
- your full identity string,
- the local namespace and public key information.

### List peers

```text
peers
```

This is the default for the `peers` command family. It shows each known peer, their alias (if set), their status, and whether a route is cached or reachable.

You can also request explicit subcommands:

```text
peers list
peers add <namespace::full-public-key-hex>
peers remove <number>
peers alias <number> <alias>
```

A peer ID must be the full public key, not a short fingerprint. The project intentionally rejects short fingerprints for `peers add` because the code requires the full key for verification and encryption.

### Add a peer

When you know another user's identity, add it like this:

```text
peers add alice::0123abcd...
```

The value is expected to be:

```text
<namespace>::<full-ed25519-public-key-hex>
```

If you want a friendlier label, set an alias:

```text
peers alias 1 friend
```

To clear an alias:

```text
peers alias 1 --clear
```

### Send a message

```text
send
```

The client prompts you in sequence:

1. select the recipient by number, alias, or identity,
2. type a subject,
3. type the message body,
4. end the body with a line containing only `.`

Example interaction:

```text
inkmail> send

Select recipient:
1. alice::deadbeef (friend)

Recipient (number, alias or identity): friend

Sending to alice::deadbeef (friend)

Subject: Hello
Enter message body. A single '.' on its own line sends the message.
Hi there.
.

Sending message...
```

The message is created, saved locally as queued, and then sent through the resolved network path.

### List messages and folders

The mailbox is organized into folders:

- `inbox` (default when you run `msg`)
- `archive`
- `important`
- `deleted`

Display the current mailbox:

```text
msg
```

Or display a specific folder:

```text
msg archive
msg important
```

Open a stored message:

```text
open <message-id>
```

This prints the message metadata, subject, and body.

### Move and delete messages

Move a message to another folder:

```text
msg mv <message-id> archive
```

Delete a message:

```text
msg del <message-id>
```

These operations are signed with your identity and then replicated to Daddy/relays so the mailbox state can converge across devices.

### Sync mailbox state

Mailbox operations are synchronized from Daddy. To pull any newer signed operations:

```text
msg sync
```

This updates the local mailbox watermark and reapplies valid move/delete operations for your own messages.

### Relay status and probing

See the configured relay/Daddy list:

```text
relays
```

Probe each known relay for latency:

```text
relays probe
```

This shows each relay address and its measured round-trip time in milliseconds. A value of `-1` indicates an unreachable relay.

## Direct delivery and relay fallback

InkMail attempts to deliver messages in this order:

1. use a cached or discovered route for the recipient,
2. dial the recipient directly over the ghost network,
3. if direct delivery is not possible, send the encrypted envelope to Daddy or a configured relay,
4. rely on Daddy to hold the message until the recipient fetches it.

This means the client can continue working when IP addresses change or when either side is behind NAT. The route registration is time-limited, and stale routes are replaced by newer registrations.

## relays.conf and relay configuration

InkMail looks for a relay list in:

- `~/.inkmail/relays.conf` by default,
- or a path passed via the daemon or environment.

The format supports either a simple list or named sections:

```ini
# simple list
relay.example.com:25565

# named entries
[relay "home"]
address = relay.example.com:25565
priority = 10
```

You can also provide relay addresses via environment variables:

```bash
export INKMAIL_RELAYS="relay1.example.com:25565 relay2.example.com:25565"
```

The code also honours `INKMAIL_DADDY` for compatibility and `INKMAIL_DATA_DIR` for the default data directory location.

## Running the daemon

The daemon listens for inbound ghost-network connections and maintains persistent connectivity to your configured relay node.

Example:

```bash
./build/inkmaild --data ~/.inkmail --port 25565 --daddy 129.150.63.22:25565
```

If you want to disable the default Daddy fallback, pass an empty value:

```bash
./build/inkmaild --data ~/.inkmail --port 25565 --daddy ""
```

The daemon logs the identity, the relay list, and the listening port. It is intended to be the background service that receives at the network layer while the CLI remains the interactive user interface.

## Security and trust model

InkMail’s model is based on layered security:

- identity keys are Ed25519 signatures that attest to who sent a message,
- message content is encrypted with X25519-derived keys before it leaves the sender,
- the transport layer also performs encrypted sessions after a signed handshake,
- relays and Daddy only receive encrypted content and routing metadata, not your plaintext.

The project explicitly validates:

- peer namespaces and public keys,
- message and encrypted-envelope signatures,
- recipient identities,
- route TTLs,
- mailbox operation author ownership.

This reduces the risk of spoofed identities, forged mail, or route poisoning.

## Practical usage notes

A typical workflow is:

```bash
./build/inkmail --data ~/.inkmail --user alice
```

Then inside the client:

```text
identity
peers add bob::<full-public-key>
peers alias 1 bob
send
msg
msg sync
```

For long-lived operation, run the daemon in a separate terminal or as a service, and leave the interactive client for reading and sending messages.

## Troubleshooting

- If `peers add` fails, check that you used the full public key and the correct `namespace::public-key` syntax.
- If delivery is slow or fails, run `relays probe` to check connectivity.
- If you have no peer routes yet, use `peers` to confirm identity records are present before sending.
- If a message is still queued, it means the client accepted it locally but did not yet get a direct or relayed acknowledgement.

## Related documentation

- [INSTALL.md](INSTALL.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)

## Licensing and project status

This repository does not currently include a license file in the workspace snapshot provided to me, so license terms should be checked before redistribution or public deployment.

The code in this repository is a working prototype/CLI project and the user-facing behavior should be treated as a local-usage tool rather than a finished public service without additional review, deployment hardening, and operational monitoring.

---

_FtR InkMail Mail Protocol, version 1.0.0, written by Quan Thai_
