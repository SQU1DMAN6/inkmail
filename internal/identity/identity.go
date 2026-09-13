package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

type Identity struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

func LoadOrCreate(dir string) (*Identity, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
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
			PublicKey: append(
				ed25519.PublicKey(nil),
				public...,
			),
			PrivateKey: ed25519.PrivateKey(private),
		}, nil
	}

	if !os.IsNotExist(err) {
		return nil, err
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
		return nil, err
	}

	if err := os.WriteFile(
		publicPath,
		public,
		0644,
	); err != nil {
		return nil, err
	}

	return &Identity{
		PublicKey:  public,
		PrivateKey: private,
	}, nil
}

func Fingerprint(
	publicKey ed25519.PublicKey,
) string {
	return hex.EncodeToString(
		publicKey[:8],
	)
}
