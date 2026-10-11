package relay

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"ipvrelay/internal/vpnapi"
)

// probeTimeout is deliberately short: a server that does not answer within
// this budget is not worth showing a number for.
const probeTimeout = 1200 * time.Millisecond

// prober measures ICMP round-trip time to candidates. Kernel servers answer
// ICMP; the official client relies on the same signal. It uses the unprivileged
// ICMP socket (SOCK_DGRAM) and only falls back to raw sockets when the system
// forbids that, which needs CAP_NET_RAW.
type prober struct {
	mu   sync.Mutex
	conn *icmp.PacketConn

	id  int
	seq int
}

// newProber opens an ICMP socket. A nil prober is returned when neither mode
// works, and callers simply leave latency unmeasured.
func newProber() (*prober, error) {
	for _, network := range []string{"udp4", "ip4:icmp"} {
		conn, err := icmp.ListenPacket(network, "0.0.0.0")
		if err == nil {
			return &prober{conn: conn, id: os.Getpid() & 0xffff}, nil
		}
	}
	return nil, fmt.Errorf("relay: no usable ICMP socket")
}

func (p *prober) Close() error {
	if p == nil || p.conn == nil {
		return nil
	}
	return p.conn.Close()
}

// ping returns the round-trip time to ip, or an error if it did not answer.
func (p *prober) ping(ctx context.Context, ip netip.Addr) (time.Duration, error) {
	if p == nil || !ip.Is4() {
		return 0, fmt.Errorf("relay: ping unsupported for %s", ip)
	}

	p.mu.Lock()
	p.seq++
	seq := p.seq & 0xffff
	id := p.id
	p.mu.Unlock()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("ipvrelay"),
		},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	dst := &net.IPAddr{IP: ip.AsSlice()}
	deadline := time.Now().Add(probeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := p.conn.SetWriteDeadline(time.Now().Add(probeTimeout)); err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := p.conn.WriteTo(wire, dst); err != nil {
		return 0, err
	}

	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		if err := p.conn.SetReadDeadline(deadline); err != nil {
			return 0, err
		}
		n, peer, err := p.conn.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		if peer.String() != dst.IP.String() {
			continue
		}
		reply, err := icmp.ParseMessage(protocolICMP, buf[:n])
		if err != nil || reply.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if !ok || echo.ID != id || echo.Seq != seq {
			continue
		}
		return time.Since(start), nil
	}
	return 0, fmt.Errorf("relay: no echo reply from %s", ip)
}

// protocolICMP is the protocol number icmp.ParseMessage wants.
const protocolICMP = 1

// probeAll pings every server that is not already measured, a few at a time,
// and reports each result as it arrives.
func (p *prober) probeAll(ctx context.Context, servers []vpnapi.Server, report func(hostname string, rtt time.Duration)) {
	const workers = 24

	queue := make(chan vpnapi.Server)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for s := range queue {
				if ctx.Err() != nil {
					return
				}
				ip, err := netip.ParseAddr(s.IP)
				if err != nil {
					continue
				}
				if rtt, err := p.ping(ctx, ip); err == nil {
					report(s.Hostname, rtt)
				}
			}
		}()
	}

	for _, s := range servers {
		select {
		case queue <- s:
		case <-ctx.Done():
			close(queue)
			wg.Wait()
			return
		}
	}
	close(queue)
	wg.Wait()
}

// jittered spreads repeat probes so we do not hammer every endpoint at once.
func jittered(d time.Duration) time.Duration {
	return d + time.Duration(rand.Int63n(int64(d/2+1)))
}
