package network

// failover.go tries each configured relay in turn so one dead Daddy never blocks a send, lookup or fetch (SPEC v0.5 sections 18, 19, Tests E/F).

import (
	"strings"

	"github.com/SQU1DMAN6/inkmail/internal/database"
	"github.com/SQU1DMAN6/inkmail/internal/identity"
	"github.com/SQU1DMAN6/inkmail/internal/message"
)

func holdViaRelays(
	local *identity.Identity,
	db *database.Database,
	daddies []string,
	envelope *message.MailboxEnvelope,
) bool {
	for _, daddy := range daddies {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		if err := SendHoldMessage(daddy, local, db, envelope); err == nil {
			return true
		}
	}

	return false
}

// fetchViaRelays collects held envelopes from each relay in turn. It returns
// the total stored locally; one dead Daddy must not block the others.
func fetchViaRelays(
	daddies []string,
	local *identity.Identity,
	db *database.Database,
) (int, error) {
	total := 0

	var lastErr error

	for _, daddy := range daddies {
		if strings.TrimSpace(daddy) == "" {
			continue
		}

		delivered, err := FetchHeldMessages(daddy, local, db)
		if err != nil {
			lastErr = err

			continue
		}

		total += delivered
	}

	if total == 0 && lastErr != nil {
		return 0, lastErr
	}

	return total, nil
}
