package relay

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// keyPair is a WireGuard key pair generated locally. The private half never
// leaves the machine.
type keyPair struct {
	Private string
	Public  string
}

// generateKeyPair mirrors what wg genkey produces: 32 random bytes with the
// Curve25519 clamping applied.
func generateKeyPair() (keyPair, error) {
	priv := make([]byte, 32)
	if _, err := rand.Read(priv); err != nil {
		return keyPair{}, fmt.Errorf("relay: key generation failed: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return keyPair{}, fmt.Errorf("relay: public key derivation failed: %w", err)
	}
	return keyPair{
		Private: base64.StdEncoding.EncodeToString(priv),
		Public:  base64.StdEncoding.EncodeToString(pub),
	}, nil
}
