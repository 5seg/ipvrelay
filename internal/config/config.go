// Package config persists credentials and settings.
//
// The account password is never written to disk. The first run exchanges it for
// a refresh token and only the tokens are stored, in a 0600 file under
// $XDG_STATE_HOME/ipvrelay (default ~/.local/state/ipvrelay).
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// State is everything persisted between runs.
type State struct {
	Email        string    `json:"email"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	// APIToken is the app credential. Empty means "use the built-in default".
	APIToken string `json:"api_token,omitempty"`
	// Backend remembers the last chosen tunnel backend ("kernel"/"userspace").
	Backend string `json:"backend,omitempty"`
	// LastServer is the hostname to reconnect to on start.
	LastServer string `json:"last_server,omitempty"`
	// Assignment is the last WireGuard assignment that worked. See
	// assignment.go for why it is kept.
	Assignment *Assignment `json:"assignment,omitempty"`
}

// Path returns the state file location, honouring IPVRELAY_STATE.
func Path() (string, error) {
	if p := os.Getenv("IPVRELAY_STATE"); p != "" {
		return p, nil
	}
	dir := os.Getenv("XDG_STATE_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("config: locate home: %w", err)
		}
		dir = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(dir, "ipvrelay", "state.json"), nil
}

// Load reads the state file. A missing file is not an error: it returns an
// empty State so the caller can run the first-time flow.
func Load() (State, error) {
	path, err := Path()
	if err != nil {
		return State{}, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return State{}, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return State{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	return s, nil
}

// Save writes the state atomically with 0600 permissions, creating the parent
// directory with 0700 if needed.
func Save(s State) error {
	path, err := Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: create %s: %w", dir, err)
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return fmt.Errorf("config: temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("config: chmod: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return fmt.Errorf("config: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("config: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("config: rename: %w", err)
	}
	return nil
}

// Clear removes the state file.
func Clear() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
