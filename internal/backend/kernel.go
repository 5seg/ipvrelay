package backend

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"ipvrelay/internal/vpnapi"
)

// routeTable is the routing table that holds the tunnel default route. The
// main table is never modified; a source-based rule selects this table only
// for traffic originating from the tunnel address.
const routeTable = 1000

// rulePriority keeps the source rule ahead of the main lookup (32766).
const rulePriority = 5209

type kernel struct {
	iface string
	logf  func(string, ...any)

	mu     sync.RWMutex
	link   netlink.Link
	addr   netip.Addr
	client *wgctrl.Client
	res    *net.Resolver
}

func newKernel(iface string, logf func(string, ...any)) *kernel {
	return &kernel{iface: iface, logf: logf}
}

func (k *kernel) Name() string { return "kernel" }

func (k *kernel) Configure(ctx context.Context, cfg vpnapi.WireGuardConfig) error {
	if err := ensureModule(); err != nil {
		return err
	}
	prefix, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return fmt.Errorf("kernel: address %q: %w", cfg.Address, err)
	}
	addr := prefix.Addr()

	priv, err := parseKey(cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("kernel: private key: %w", err)
	}
	pub, err := parseKey(cfg.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("kernel: peer key: %w", err)
	}
	endpoint, err := net.ResolveUDPAddr("udp", cfg.PeerEndpoint)
	if err != nil {
		return fmt.Errorf("kernel: endpoint %q: %w", cfg.PeerEndpoint, err)
	}

	link, err := ensureLink(k.iface)
	if err != nil {
		return err
	}

	client, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("kernel: wgctrl: %w", err)
	}

	peer := wgtypes.PeerConfig{
		PublicKey:         pub,
		Endpoint:          endpoint,
		ReplaceAllowedIPs: true,
	}
	for _, ip := range allowedIPs(cfg) {
		_, n, err := net.ParseCIDR(ip)
		if err != nil {
			client.Close()
			return fmt.Errorf("kernel: allowed ip %q: %w", ip, err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, *n)
	}
	devCfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: true,
		Peers:        []wgtypes.PeerConfig{peer},
	}
	if err := client.ConfigureDevice(k.iface, devCfg); err != nil {
		client.Close()
		return fmt.Errorf("kernel: configure %s: %w", k.iface, err)
	}

	// One address at a time: stale /32s from earlier servers must go.
	if err := replaceAddress(link, addr); err != nil {
		client.Close()
		return err
	}
	if err := netlink.LinkSetUp(link); err != nil {
		client.Close()
		return fmt.Errorf("kernel: link up: %w", err)
	}
	if err := installRouting(link, addr); err != nil {
		client.Close()
		return err
	}

	res := resolverFor(addr, tunnelDNS(cfg))

	k.mu.Lock()
	k.link, k.addr, k.res = link, addr, res
	if k.client != nil {
		k.client.Close()
	}
	k.client = client
	k.mu.Unlock()

	k.logf("tunnel up on %s via %s (table %d)", addr, cfg.PeerEndpoint, routeTable)
	return nil
}

func (k *kernel) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	k.mu.RLock()
	addr, res := k.addr, k.res
	k.mu.RUnlock()
	if !addr.IsValid() {
		return nil, fmt.Errorf("kernel: tunnel is not configured")
	}

	d := net.Dialer{Resolver: res}
	switch {
	case strings.HasPrefix(network, "tcp"):
		d.LocalAddr = &net.TCPAddr{IP: addr.AsSlice()}
	case strings.HasPrefix(network, "udp"):
		d.LocalAddr = &net.UDPAddr{IP: addr.AsSlice()}
	}
	return d.DialContext(ctx, network, address)
}

func (k *kernel) Close() error {
	k.mu.Lock()
	client := k.client
	link := k.link
	addr := k.addr
	k.client, k.link = nil, nil
	k.mu.Unlock()

	if client != nil {
		client.Close()
	}
	if link != nil && addr.IsValid() {
		removeRouting(addr)
	}
	return nil
}

// resolverFor builds a resolver whose queries leave through the tunnel.
//
// The lookup target is forced to the tunnel's own resolver: the destination
// from net.Resolver comes from /etc/resolv.conf, which points at the local
// network and would be sent into the tunnel to no effect.
func resolverFor(addr, dns netip.Addr) *net.Resolver {
	target := net.JoinHostPort(dns.String(), "53")
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{}
			if strings.HasPrefix(network, "tcp") {
				d.LocalAddr = &net.TCPAddr{IP: addr.AsSlice()}
			} else {
				d.LocalAddr = &net.UDPAddr{IP: addr.AsSlice()}
			}
			return d.DialContext(ctx, network, target)
		},
	}
}

// tunnelDNS picks the resolver the assignment told us to use.
func tunnelDNS(cfg vpnapi.WireGuardConfig) netip.Addr {
	for _, d := range cfg.DNSServers {
		if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil && a.Is4() {
			return a
		}
	}
	return netip.MustParseAddr("1.1.1.1")
}

func ensureLink(name string) (netlink.Link, error) {
	if link, err := netlink.LinkByName(name); err == nil {
		return link, nil
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = name
	wg := &netlink.Wireguard{LinkAttrs: attrs}
	if err := netlink.LinkAdd(wg); err != nil {
		return nil, fmt.Errorf("kernel: create %s: %w", name, err)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, fmt.Errorf("kernel: find %s: %w", name, err)
	}
	return link, nil
}

func replaceAddress(link netlink.Link, addr netip.Addr) error {
	existing, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("kernel: list addresses: %w", err)
	}
	want := &netlink.Addr{IPNet: &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(32, 32)}}
	for _, a := range existing {
		if a.IPNet != nil && a.IPNet.IP.Equal(addr.AsSlice()) {
			continue
		}
		if err := netlink.AddrDel(link, &a); err != nil {
			return fmt.Errorf("kernel: remove address %s: %w", a.IPNet, err)
		}
	}
	if err := netlink.AddrReplace(link, want); err != nil {
		return fmt.Errorf("kernel: set address %s: %w", addr, err)
	}
	return nil
}

// installRouting sends traffic sourced from the tunnel address through the
// tunnel without touching the main table.
func installRouting(link netlink.Link, addr netip.Addr) error {
	// netlink wants an explicit 0.0.0.0/0 here; a nil Dst is rejected.
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Table:     routeTable,
		Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("kernel: default route in table %d: %w", routeTable, err)
	}
	if err := removeRouting(addr); err != nil {
		return err
	}
	rule := netlink.NewRule()
	rule.Src = &net.IPNet{IP: addr.AsSlice(), Mask: net.CIDRMask(32, 32)}
	rule.Table = routeTable
	rule.Priority = rulePriority
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("kernel: source rule for %s: %w", addr, err)
	}
	return nil
}

func removeRouting(addr netip.Addr) error {
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("kernel: list rules: %w", err)
	}
	for _, r := range rules {
		if r.Src == nil || !r.Src.IP.Equal(addr.AsSlice()) || r.Table != routeTable {
			continue
		}
		if err := netlink.RuleDel(&r); err != nil {
			return fmt.Errorf("kernel: delete rule: %w", err)
		}
	}
	return nil
}

func parseKey(b64 string) (wgtypes.Key, error) {
	var k wgtypes.Key
	raw, err := decodeKey(b64)
	if err != nil {
		return k, err
	}
	copy(k[:], raw)
	return k, nil
}

// ensureModule loads the wireguard module when it is not already present.
func ensureModule() error {
	if _, err := os.Stat("/sys/module/wireguard"); err == nil {
		return nil
	}
	path, err := exec.LookPath("modprobe")
	if err != nil {
		return fmt.Errorf("kernel: wireguard module is not loaded and modprobe is unavailable")
	}
	out, err := exec.Command(path, "wireguard").CombinedOutput()
	if err != nil {
		return fmt.Errorf("kernel: modprobe wireguard: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// KernelAvailable reports whether the kernel backend can be used right now:
// the caller holds CAP_NET_ADMIN and the wireguard module is loadable or
// already loaded.
func KernelAvailable() bool {
	if _, err := os.Stat("/sys/module/wireguard"); err != nil {
		if _, err := exec.LookPath("modprobe"); err != nil {
			return false
		}
	}
	return hasCapNetAdmin()
}

// hasCapNetAdmin checks CAP_NET_ADMIN in the effective capability set, which
// catches both root and file capabilities.
func hasCapNetAdmin() bool {
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return os.Geteuid() == 0
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		v, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			break
		}
		return v&(1<<12) != 0 // CAP_NET_ADMIN
	}
	return os.Geteuid() == 0
}
