package backend

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"ipvrelay/internal/vpnapi"
)

// drainGrace is how long a replaced tunnel stays alive so that in-flight
// connections can finish. Switching servers should not break a page load that
// is already in progress.
const drainGrace = 90 * time.Second

// mtu matches the value the official clients use on the same endpoints.
const mtu = 1420

type userspace struct {
	logf func(string, ...any)

	mu      sync.RWMutex
	dev     *device.Device
	net     *netstack.Net
	old     []*device.Device
	closing bool
}

func newUserspace(logf func(string, ...any)) *userspace {
	return &userspace{logf: logf}
}

func (u *userspace) Name() string { return "userspace" }

func (u *userspace) Configure(ctx context.Context, cfg vpnapi.WireGuardConfig) error {
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("userspace: address %q: %w", cfg.Address, err)
	}
	var dns []netip.Addr
	for _, d := range cfg.DNSServers {
		a, err := netip.ParseAddr(strings.TrimSpace(d))
		if err != nil {
			return fmt.Errorf("userspace: dns %q: %w", d, err)
		}
		dns = append(dns, a)
	}

	priv, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("userspace: private key: %w", err)
	}
	pub, err := keyToHex(cfg.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("userspace: peer key: %w", err)
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr.Addr()}, dns, mtu)
	if err != nil {
		return fmt.Errorf("userspace: netstack: %w", err)
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "wg "))

	ipc := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=15\n",
		priv, pub, cfg.PeerEndpoint)
	for _, ip := range allowedIPs(cfg) {
		ipc += "allowed_ip=" + ip + "\n"
	}
	if err := dev.IpcSet(ipc); err != nil {
		dev.Close()
		return fmt.Errorf("userspace: configure device: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("userspace: bring up: %w", err)
	}

	u.mu.Lock()
	if u.closing {
		u.mu.Unlock()
		dev.Close()
		return fmt.Errorf("userspace: shutting down")
	}
	previous := u.dev
	u.dev, u.net = dev, tnet
	if previous != nil {
		u.old = append(u.old, previous)
	}
	u.mu.Unlock()

	u.logf("tunnel up on %s via %s", addr.Addr(), cfg.PeerEndpoint)
	if previous != nil {
		go u.retire(previous)
	}
	return nil
}

// retire closes a replaced device once the grace period is over.
func (u *userspace) retire(dev *device.Device) {
	time.Sleep(drainGrace)
	dev.Close()

	u.mu.Lock()
	for i, d := range u.old {
		if d == dev {
			u.old = append(u.old[:i], u.old[i+1:]...)
			break
		}
	}
	u.mu.Unlock()
}

func (u *userspace) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	u.mu.RLock()
	tnet := u.net
	u.mu.RUnlock()
	if tnet == nil {
		return nil, fmt.Errorf("userspace: tunnel is not configured")
	}
	return tnet.DialContext(ctx, network, address)
}

func (u *userspace) Close() error {
	u.mu.Lock()
	u.closing = true
	devs := append([]*device.Device{u.dev}, u.old...)
	u.dev, u.net, u.old = nil, nil, nil
	u.mu.Unlock()

	for _, d := range devs {
		if d != nil {
			d.Close()
		}
	}
	return nil
}

// allowedIPs returns the peer's allowed IPs, defaulting to a full tunnel.
func allowedIPs(cfg vpnapi.WireGuardConfig) []string {
	if len(cfg.AllowedIPs) == 0 {
		return []string{"0.0.0.0/0"}
	}
	return cfg.AllowedIPs
}

// keyToHex converts a base64 WireGuard key to the hex form the UAPI expects.
func keyToHex(b64 string) (string, error) {
	raw, err := decodeKey(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
