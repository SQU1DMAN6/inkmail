# Installing InkMail from source

This guide explains how to build InkMail and its daemon directly from this repository.

## Requirements

- Go toolchain installed and available in `PATH`
- A Unix-like environment (Linux/macOS; this codebase is built and tested in a Linux workspace, builds for Windows may come out in the future)
- A normal user account with write permission to the destination directory

The repository declares:

```go
module github.com/SQU1DMAN6/inkmail

go 1.27.0
```

That means a Go toolchain new enough to support the module version declared in the project is expected.

## Download Go dependencies

```bash
go mod download
```

## Build the binaries

The project includes a `Makefile` with the expected build targets:

```bash
make build
```

This runs:

```bash
go build -o build/inkmaild ./cmd/inkmaild/
go build -o build/inkmail ./cmd/inkmail/
```

After building, the executables appear under the repository’s `build/` directory.

## Install to a system path

If you want the commands available on your `PATH`:

```bash
sudo install -m 0755 build/inkmail /usr/local/bin/inkmail
sudo install -m 0755 build/inkmaild /usr/local/bin/inkmaild
```

## First run

### Start the interactive client

```bash
inkmail --data ~/.inkmail --user alice
```

This creates the data directory if it does not exist. The first run generates a keypair and stores it under `~/.inkmail/identity`, as well as sets the namespace within the identity to "alice".

### Start the daemon

```bash
inkmaild --data ~/.inkmail --port 25565 --daddy 129.150.63.22:25565
```

This creates or reuses the same data directory and runs a listener on the selected port.

If you want to disable the default Daddy dependency and rely only on a local relay list, use:

```bash
inkmaild --data ~/.inkmail --port 25565 --daddy ""
```

## Default data location and file layout

By default the app uses:

```bash
$HOME/.inkmail
```

Common files created there include:

- `identity/private.key`
- `identity/public.key`
- `identity/enc_private.key`
- `identity/enc_public.key`
- `identity/namespace`
- `node.db`
- `relays.conf` (when you deploy a custom relay list)

The daemon also updates metadata such as the configured listening port and route state inside the SQLite database.

## Build verification

The project exposes a `vet` target:

```bash
make vet
```

This runs:

```bash
go vet ./...
```

This is a good sanity check before using a fresh build in production-like deployment scenarios.

## Local testing workflow

A simple development workflow is:

```bash
make build
./build/inkmail --data /tmp/inkmail-a --user alice
./build/inkmail --data /tmp/inkmail-b --user bob
```

Then add each peer using the full identity string and send a message.

## Notes

- The application expects both users to know each other’s full identity strings before sending.
- The CLI is interactive and intentionally not a web dashboard.
- For real deployment, scrutinize relay trust, port forwarding, firewall policy, and host security before exposing a node on the internet.

See also:

- [README.md](README.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
