package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	defaultNamespace = "user"
	maxNamespaceLen  = 64
)

type Identity struct {
	Namespace  string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func LoadOrCreate(
	dir string,
	requestedNamespace string,
) (*Identity, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf(
			"create identity directory: %w",
			err,
		)
	}

	namespace, err := loadOrCreateNamespace(
		dir,
		requestedNamespace,
	)
	if err != nil {
		return nil, err
	}

	privatePath := filepath.Join(
		dir,
		"private.key",
	)

	publicPath := filepath.Join(
		dir,
		"public.key",
	)

	private, err := os.ReadFile(privatePath)

	if err == nil {
		if len(private) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf(
				"invalid private key size",
			)
		}

		public := private[ed25519.SeedSize:]

		return &Identity{
			Namespace: namespace,
			PublicKey: append(
				ed25519.PublicKey(nil),
				public...,
			),
			PrivateKey: append(
				ed25519.PrivateKey(nil),
				private...,
			),
		}, nil
	}

	if !os.IsNotExist(err) {
		return nil, fmt.Errorf(
			"read private key: %w",
			err,
		)
	}

	public, private, err := ed25519.GenerateKey(
		rand.Reader,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"generate identity: %w",
			err,
		)
	}

	if err := os.WriteFile(
		privatePath,
		private,
		0600,
	); err != nil {
		return nil, fmt.Errorf(
			"write private key: %w",
			err,
		)
	}

	if err := os.WriteFile(
		publicPath,
		public,
		0644,
	); err != nil {
		return nil, fmt.Errorf(
			"write public key: %w",
			err,
		)
	}

	return &Identity{
		Namespace:  namespace,
		PublicKey:  public,
		PrivateKey: private,
	}, nil
}

func loadOrCreateNamespace(
	dir string,
	requestedNamespace string,
) (string, error) {
	namespacePath := filepath.Join(
		dir,
		"namespace",
	)

	stored, err := os.ReadFile(namespacePath)

	if err == nil {
		namespace := strings.TrimSpace(
			string(stored),
		)

		if err := ValidateNamespace(namespace); err != nil {
			return "", fmt.Errorf(
				"invalid stored namespace: %w",
				err,
			)
		}

		if requestedNamespace != "" &&
			requestedNamespace != namespace {
			return "", fmt.Errorf(
				"identity already uses namespace %q; refusing to change it to %q",
				namespace,
				requestedNamespace,
			)
		}

		return namespace, nil
	}

	if !os.IsNotExist(err) {
		return "", fmt.Errorf(
			"read namespace: %w",
			err,
		)
	}

	namespace := requestedNamespace

	if namespace == "" {
		namespace = defaultNamespace
	}

	if err := ValidateNamespace(namespace); err != nil {
		return "", err
	}

	if err := os.WriteFile(
		namespacePath,
		[]byte(namespace+"\n"),
		0600,
	); err != nil {
		return "", fmt.Errorf(
			"write namespace: %w",
			err,
		)
	}

	return namespace, nil
}

func ValidateNamespace(namespace string) error {
	if namespace == "" {
		return fmt.Errorf(
			"namespace cannot be empty",
		)
	}

	if len(namespace) > maxNamespaceLen {
		return fmt.Errorf(
			"namespace cannot exceed %d characters",
			maxNamespaceLen,
		)
	}

	if strings.Contains(namespace, "::") {
		return fmt.Errorf(
			"namespace cannot contain %q",
			"::",
		)
	}

	for _, character := range namespace {
		if unicode.IsSpace(character) ||
			unicode.IsControl(character) {
			return fmt.Errorf(
				"namespace cannot contain whitespace or control characters",
			)
		}
	}

	return nil
}

func Fingerprint(
	publicKey ed25519.PublicKey,
) string {
	if len(publicKey) < 8 {
		return hex.EncodeToString(publicKey)
	}

	return hex.EncodeToString(
		publicKey[:8],
	)
}

func Address(
	id *Identity,
) string {
	return fmt.Sprintf(
		"%s::%s",
		id.Namespace,
		Fingerprint(id.PublicKey),
	)
}

func FingerprintFromHex(
	publicKey string,
) string {
	decoded, err := hex.DecodeString(publicKey)
	if err != nil {
		return publicKey
	}

	if len(decoded) < 8 {
		return hex.EncodeToString(decoded)
	}

	return hex.EncodeToString(
		decoded[:8],
	)
}
