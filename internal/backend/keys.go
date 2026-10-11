package backend

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// decodeKey turns a base64 WireGuard key into its 32 raw bytes.
func decodeKey(b64 string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	return raw, nil
}
