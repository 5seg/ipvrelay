package config

import "ipvrelay/internal/vpnapi"

// Assignment is the last WireGuard assignment that worked, kept so the tunnel
// can be rebuilt after a restart even when the API is unreachable.
//
// It holds a private key, which is why it lives in the same 0600 file as the
// session tokens.
type Assignment = vpnapi.WireGuardConfig

// LastAssignment returns the stored assignment, if any.
func (s State) LastAssignment() (Assignment, bool) {
	if s.Assignment == nil || s.Assignment.PrivateKey == "" {
		return Assignment{}, false
	}
	return *s.Assignment, true
}

// SetAssignment records an assignment.
func (s *State) SetAssignment(a Assignment) { s.Assignment = &a }
