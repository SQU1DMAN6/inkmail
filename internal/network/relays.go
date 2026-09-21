package network

// relays.go implements the Ghost Networking relay list (SPEC v0.5 sections 18,
// 19, Tests E/F). Configuration moves from a single `daddy_address` toward
// `relays.conf`. See ParseRelays for the accepted syntax.

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
)

// Relay is one configured Daddy/relay endpoint.
type Relay struct {
	Name     string
	Address  string
	Priority int
}

// DefaultRelayPriority is used when relays.conf omits `priority =`.
const DefaultRelayPriority = 100

// DefaultDaddyAddress is the built-in fallback when no relay is configured.
const DefaultDaddyAddress = "129.150.63.22:25565"

// RelaysFileName is the file searched inside the InkMail data directory.
const RelaysFileName = "relays.conf"

// DefaultRelaysDir returns the data directory holding relays.conf.
func DefaultRelaysDir() string {
	if dir := strings.TrimSpace(os.Getenv("INKMAIL_DATA_DIR")); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return filepath.Join(home, ".inkmail")
}

// DefaultRelaysPath returns the default relays.conf path.
func DefaultRelaysPath() string {
	return filepath.Join(DefaultRelaysDir(), RelaysFileName)
}

// ParseRelays parses relays.conf content. Both forms are accepted:
//
// [relay "name"]
// address = host:port
// priority = 10
//
// and bare `host:port` lines. Unknown keys are ignored so future options
// do not break old clients.
func ParseRelays(content string) ([]Relay, error) {
	var relays []Relay
	current := -1
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inner := strings.TrimSpace(line[1 : len(line)-1])
			relays = append(relays, Relay{Name: sectionName(inner), Priority: DefaultRelayPriority})
			current = len(relays) - 1
			continue
		}
		key, value, hasEquals := splitKeyValue(line)
		if hasEquals {
			if current < 0 {
				continue
			}
			switch strings.ToLower(key) {
			case "address":
				relays[current].Address = value
			case "priority":
				priority, err := strconv.Atoi(strings.TrimSpace(value))
				if err != nil {
					return nil, fmt.Errorf("invalid priority %q: %w", value, err)
				}
				relays[current].Priority = priority
			default:
			}
			continue
		}
		address := strings.TrimSpace(line)
		if err := validateRelayAddress(address); err != nil {
			return nil, err
		}
		relays = append(relays, Relay{Name: address, Address: address, Priority: DefaultRelayPriority})
		current = len(relays) - 1
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse relays.conf: %w", err)
	}
	cleaned := make([]Relay, 0, len(relays))
	for _, relay := range relays {
		relay.Address = strings.TrimSpace(relay.Address)
		if relay.Address == "" {
			continue
		}
		if err := validateRelayAddress(relay.Address); err != nil {
			return nil, err
		}
		if strings.TrimSpace(relay.Name) == "" {
			relay.Name = relay.Address
		}
		cleaned = append(cleaned, relay)
	}
	return cleaned, nil
}

// sectionName extracts the relay name from `[relay "name"]` or `[name]`.
func sectionName(inner string) string {
	fields := strings.Fields(inner)
	if len(fields) == 0 {
		return ""
	}
	if len(fields) == 1 {
		return strings.Trim(fields[0], "'\"")
	}
	return strings.Trim(strings.Join(fields[1:], " "), "'\"")
}

// splitKeyValue splits `key = value` / `key: value` pairs.
func splitKeyValue(line string) (string, string, bool) {
	for _, sep := range []string{"=", ":"} {
		if idx := strings.Index(line, sep); idx >= 0 {
			return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+len(sep):]), true
		}
	}
	return "", "", false
}

// validateRelayAddress rejects empty or malformed host:port values.
func validateRelayAddress(address string) error {
	address = strings.TrimSpace(address)
	if address == "" {
		return fmt.Errorf("relay address cannot be empty")
	}
	return validateAdvertisedAddress(address)
}

// OrderRelays sorts relays by priority, then name, then address.
func OrderRelays(relays []Relay) []Relay {
	ordered := append([]Relay(nil), relays...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].Priority != ordered[j].Priority {
			return ordered[i].Priority < ordered[j].Priority
		}
		if ordered[i].Name != ordered[j].Name {
			return ordered[i].Name < ordered[j].Name
		}
		return ordered[i].Address < ordered[j].Address
	})
	return ordered
}

// SelectRelays returns relays in dial order with jitter inside each
// priority band so clients spread load (SPEC v0.5 section 19).
func SelectRelays(relays []Relay) []Relay {
	ordered := OrderRelays(relays)
	start := 0
	for start < len(ordered) {
		end := start + 1
		for end < len(ordered) && ordered[end].Priority == ordered[start].Priority {
			end++
		}
		for i := end - 1; i > start; i-- {
			j := start + rand.Intn(i-start+1)
			ordered[start], ordered[j] = ordered[j], ordered[start]
		}
		start = end
	}
	return ordered
}

// LoadRelaysFile reads and parses a relays.conf file. Missing file = nil, nil.
func LoadRelaysFile(path string) ([]Relay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read relays.conf: %w", err)
	}
	return ParseRelays(string(data))
}

// parseEnvRelays splits comma/whitespace separated host:port values.
func parseEnvRelays(raw string) []Relay {
	fields := strings.Fields(strings.ReplaceAll(raw, ",", " "))
	relays := make([]Relay, 0, len(fields))
	for _, address := range fields {
		address = strings.TrimSpace(address)
		if address == "" {
			continue
		}
		if err := validateRelayAddress(address); err != nil {
			continue
		}
		relays = append(relays, Relay{Name: address, Address: address, Priority: DefaultRelayPriority})
	}
	return relays
}

// DaddyAddresses returns every configured relay address in dial order
// (SPEC v0.5 sections 18, 19, Tests E/F).
func DaddyAddresses(db *database.Database, path string) []string {
	var relays []Relay
	if raw := strings.TrimSpace(os.Getenv("INKMAIL_RELAYS")); raw != "" {
		relays = append(relays, parseEnvRelays(raw)...)
	} else if raw := strings.TrimSpace(os.Getenv("INKMAIL_DADDY")); raw != "" {
		relays = append(relays, parseEnvRelays(raw)...)
	} else {
		if path == "" {
			path = DefaultRelaysPath()
		}
		if parsed, err := LoadRelaysFile(path); err == nil {
			relays = append(relays, parsed...)
		}
	}
	ordered := SelectRelays(relays)
	seen := make(map[string]struct{}, len(ordered)+2)
	addresses := make([]string, 0, len(ordered)+2)
	for _, relay := range ordered {
		address := strings.TrimSpace(relay.Address)
		if address == "" {
			continue
		}
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if legacy := strings.TrimSpace(daddyAddressFromDB(db)); legacy != "" {
		if _, ok := seen[legacy]; !ok {
			seen[legacy] = struct{}{}
			addresses = append(addresses, legacy)
		}
	}
	if len(addresses) == 0 {
		return []string{DefaultDaddyAddress}
	}
	return addresses
}
