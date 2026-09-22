package message

// mailboxop.go defines signed mailbox mutations (move/delete) that a device
// issues for its own copy of a message and replicates to Daddy so every
// device converges.
//
// Security properties:
//   - Authorship: the op is Ed25519-signed by the message owner. Daddy and
//     siblings verify the signature; a MITM or spoofer without the private
//     key cannot forge or alter an op.
//   - Binding: the signature covers message ID, op kind, folder and
//     timestamp, so a relay cannot retarget an op to another message/folder.
//   - Freshness/conflict: timestamps give last-writer-wins convergence; a
//     malicious Daddy cannot invent newer ops (no key) and replayed old ops
//     lose to newer timestamps.
//   - Confidentiality: ops carry only routing metadata (IDs, folder names),
//     never subject/body keys. A malicious Daddy learns folder labels but
//     cannot read message contents.

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Mailbox op kinds mirrored from database to avoid an import cycle.
const (
	MailboxOpMove   = "move"
	MailboxOpDelete = "delete"
)

// mailboxOpLabel domain-separates mailbox-op signatures.
const mailboxOpLabel = "inkmail-mailbox-op-v1"

// maxOpClockFuture bounds how far ahead an op timestamp may be.
const maxOpClockFuture = 15 * time.Minute

// MailboxOpRequest is the signed wire form of one move/delete mutation.
type MailboxOpRequest struct {
	MessageID string `json:"message_id"`
	Op        string `json:"op"`
	Folder    string `json:"folder,omitempty"`
	AuthorNS  string `json:"author_namespace"`
	AuthorKey string `json:"author_public_key"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

// signingBytes returns the canonical bytes covered by the op signature.
func (o *MailboxOpRequest) signingBytes() []byte {
	type unsignedOp struct {
		Label     string `json:"label"`
		MessageID string `json:"message_id"`
		Op        string `json:"op"`
		Folder    string `json:"folder"`
		AuthorNS  string `json:"author_namespace"`
		AuthorKey string `json:"author_public_key"`
		Timestamp int64  `json:"timestamp"`
	}

	data, _ := json.Marshal(unsignedOp{
		Label:     mailboxOpLabel,
		MessageID: o.MessageID,
		Op:        strings.ToLower(strings.TrimSpace(o.Op)),
		Folder:    strings.ToLower(strings.TrimSpace(o.Folder)),
		AuthorNS:  o.AuthorNS,
		AuthorKey: o.AuthorKey,
		Timestamp: o.Timestamp,
	})

	return data
}

// SignMailboxOp builds and signs a move/delete op for messageID.
func SignMailboxOp(
	signerPrivateKey ed25519.PrivateKey,
	authorNS string,
	authorPublicKey ed25519.PublicKey,
	messageID string,
	op string,
	folder string,
	timestamp int64,
) (*MailboxOpRequest, error) {
	op = strings.ToLower(strings.TrimSpace(op))

	if op != MailboxOpMove && op != MailboxOpDelete {
		return nil, fmt.Errorf("unknown mailbox op %q", op)
	}

	if strings.TrimSpace(messageID) == "" {
		return nil, fmt.Errorf("mailbox op has no message id")
	}

	if timestamp <= 0 {
		timestamp = time.Now().Unix()
	}

	req := &MailboxOpRequest{
		MessageID: strings.TrimSpace(messageID),
		Op:        op,
		Folder:    strings.ToLower(strings.TrimSpace(folder)),
		AuthorNS:  authorNS,
		AuthorKey: hex.EncodeToString(authorPublicKey),
		Timestamp: timestamp,
	}

	req.Signature = hex.EncodeToString(ed25519.Sign(
		signerPrivateKey,
		req.signingBytes(),
	))

	return req, nil
}

// Verify checks op shape, timestamp sanity and the Ed25519 signature.
func (o *MailboxOpRequest) Verify() error {
	if strings.TrimSpace(o.MessageID) == "" {
		return fmt.Errorf("mailbox op has no message id")
	}

	op := strings.ToLower(strings.TrimSpace(o.Op))

	if op != MailboxOpMove && op != MailboxOpDelete {
		return fmt.Errorf("unknown mailbox op %q", o.Op)
	}

	authorKey, err := hex.DecodeString(o.AuthorKey)
	if err != nil || len(authorKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid author public key")
	}

	signature, err := hex.DecodeString(o.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid op signature")
	}

	if o.Timestamp <= 0 {
		return fmt.Errorf("mailbox op has no timestamp")
	}

	if time.Unix(o.Timestamp, 0).After(time.Now().Add(maxOpClockFuture)) {
		return fmt.Errorf("mailbox op timestamp too far in the future")
	}

	if !ed25519.Verify(
		ed25519.PublicKey(authorKey),
		o.signingBytes(),
		signature,
	) {
		return fmt.Errorf("invalid op signature")
	}

	return nil
}
