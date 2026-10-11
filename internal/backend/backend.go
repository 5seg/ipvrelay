// Package backend owns the WireGuard tunnel and hands back a dialer whose
// traffic egresses through it.
//
// Two implementations exist and both were verified end to end:
//
//   - userspace: wireguard-go plus a gVisor netstack. Needs no privileges and
//     no TUN device; everything lives inside the process.
//   - kernel: the in-kernel WireGuard module configured over netlink, with
//     source routing so the main routing table is never touched.
//
// Detect picks kernel when it is usable and falls back to userspace.
package backend

import (
	"context"
	"errors"
	"net"

	"ipvrelay/internal/vpnapi"
)

// Backend is a configured tunnel that can be repointed at a new endpoint.
type Backend interface {
	// Name is "kernel" or "userspace".
	Name() string
	// Configure makes cfg the active endpoint. Existing connections may or
	// may not survive; callers must not depend on either behaviour.
	Configure(ctx context.Context, cfg vpnapi.WireGuardConfig) error
	// DialContext opens an outbound connection through the tunnel. Hostnames
	// are resolved inside the tunnel.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Close tears the tunnel down.
	Close() error
}

// Options configures Detect.
type Options struct {
	// Prefer names a backend to try first: "kernel", "userspace" or "".
	Prefer string
	// Iface is the kernel interface name, default "wg0".
	Iface string
	// Logf receives human-readable events. May be nil.
	Logf func(format string, args ...any)
}

// Detect returns a usable backend. It never returns a partially configured
// tunnel: Configure still has to be called with a real assignment.
//
// Kernel is preferred when the module can be loaded and CAP_NET_ADMIN is held.
// Any failure on that path falls back to userspace, which always works.
func Detect(ctx context.Context, opts Options) (Backend, error) {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	iface := opts.Iface
	if iface == "" {
		iface = "wg0"
	}

	switch opts.Prefer {
	case "userspace":
		logf("using userspace backend (requested)")
		return newUserspace(logf), nil
	case "kernel":
		if !KernelAvailable() {
			return nil, errors.New("kernel backend requested but unavailable: need CAP_NET_ADMIN and the wireguard module")
		}
		if err := ensureModule(); err != nil {
			return nil, err
		}
		logf("using kernel backend on %s", iface)
		return newKernel(iface, logf), nil
	}

	if KernelAvailable() {
		if err := ensureModule(); err == nil {
			logf("using kernel backend on %s", iface)
			return newKernel(iface, logf), nil
		} else {
			logf("kernel backend unusable (%v), falling back to userspace", err)
		}
	} else {
		logf("no CAP_NET_ADMIN, using userspace backend")
	}
	return newUserspace(logf), nil
}
