// Package proxy implements the local ingress: a SOCKS5 server (RFC 1928,
// CONNECT only) that also accepts HTTP CONNECT on the same port.
//
// Destination hostnames are never resolved here. They are handed to the dialer
// as-is so that name resolution happens inside the tunnel and cannot leak.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Dialer creates the outbound connection, normally through the WireGuard
// tunnel. It must accept hostnames and resolve them on the far side.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Stats is a snapshot of proxy activity.
type Stats struct {
	Active    int64 // currently open connections
	Total     int64 // connections accepted since start
	Failed    int64 // connections that never got established
	BytesUp   int64 // client -> destination
	BytesDown int64 // destination -> client
}

// Server is the local proxy. Create it with New and start it with Serve.
type Server struct {
	// Addr is the listen address, normally "127.0.0.1:1080".
	Addr string
	// Dial reaches the destination. Required.
	Dial Dialer
	// ResolveName, when set, is called for domain-name destinations before
	// dialing. Leave nil to pass the name straight to Dial (preferred).
	ResolveName func(ctx context.Context, host string) (string, error)
	// Logf receives human-readable events. May be nil.
	Logf func(format string, args ...any)

	stats struct {
		active, total, failed, up, down atomic.Int64
	}

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

// New returns a Server bound to addr that dials through d.
func New(addr string, d Dialer, logf func(string, ...any)) *Server {
	return &Server{Addr: addr, Dial: d, Logf: logf}
}

// Serve accepts connections until ctx is cancelled. It returns nil on a clean
// shutdown.
func (s *Server) Serve(ctx context.Context) error {
	addr := s.Addr
	if addr == "" {
		addr = "127.0.0.1:1080"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	s.mu.Lock()
	s.conns = make(map[net.Conn]struct{})
	s.mu.Unlock()

	var wg sync.WaitGroup

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = ln.Close()
			s.closeAllConns()
		case <-stop:
		}
	}()
	defer close(stop)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			wg.Wait()
			return err
		}

		s.stats.total.Add(1)
		s.stats.active.Add(1)
		s.trackConn(conn)

		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer s.stats.active.Add(-1)
			defer s.untrackConn(c)
			s.handleConn(ctx, c)
		}(conn)
	}
}

func (s *Server) trackConn(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns != nil {
		s.conns[c] = struct{}{}
	}
}

func (s *Server) untrackConn(c net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns != nil {
		delete(s.conns, c)
	}
}

func (s *Server) closeAllConns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.conns {
		_ = c.Close()
	}
}

func (s *Server) handleConn(ctx context.Context, client net.Conn) {
	defer client.Close()

	if err := client.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.stats.failed.Add(1)
		s.logf("proxy: set deadline failed: %v", err)
		return
	}

	var firstByte [1]byte
	if _, err := io.ReadFull(client, firstByte[:]); err != nil {
		s.stats.failed.Add(1)
		s.logf("proxy: read initial byte from %s failed: %v", client.RemoteAddr(), err)
		return
	}

	switch firstByte[0] {
	case 0x05:
		s.handleSOCKS5(ctx, client, firstByte[0])
	case 'C', 'c':
		s.handleHTTPConnect(ctx, client, firstByte[0])
	default:
		s.stats.failed.Add(1)
		s.logf("proxy: unknown protocol byte 0x%02x from %s", firstByte[0], client.RemoteAddr())
	}
}

func (s *Server) handleSOCKS5(ctx context.Context, client net.Conn, firstByte byte) {
	r := io.MultiReader(bytes.NewReader([]byte{firstByte}), client)

	var greeting [2]byte
	if _, err := io.ReadFull(r, greeting[:]); err != nil {
		s.stats.failed.Add(1)
		s.logf("socks5: read greeting from %s failed: %v", client.RemoteAddr(), err)
		return
	}
	if greeting[0] != 0x05 {
		s.stats.failed.Add(1)
		s.logf("socks5: unsupported version %d from %s", greeting[0], client.RemoteAddr())
		return
	}

	nmethods := int(greeting[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(client, methods); err != nil {
		s.stats.failed.Add(1)
		s.logf("socks5: read methods from %s failed: %v", client.RemoteAddr(), err)
		return
	}

	hasNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		_, _ = client.Write([]byte{0x05, 0xff})
		s.stats.failed.Add(1)
		s.logf("socks5: no acceptable auth method from %s", client.RemoteAddr())
		return
	}

	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		s.stats.failed.Add(1)
		s.logf("socks5: write greeting reply to %s failed: %v", client.RemoteAddr(), err)
		return
	}

	var reqHeader [4]byte
	if _, err := io.ReadFull(client, reqHeader[:]); err != nil {
		s.stats.failed.Add(1)
		s.logf("socks5: read request header from %s failed: %v", client.RemoteAddr(), err)
		return
	}

	if reqHeader[0] != 0x05 {
		s.stats.failed.Add(1)
		s.logf("socks5: invalid request version %d from %s", reqHeader[0], client.RemoteAddr())
		return
	}

	cmd := reqHeader[1]
	atyp := reqHeader[3]

	if cmd != 0x01 { // CMD=1 is CONNECT
		_ = sendSocks5Reply(client, 0x07) // Command not supported
		s.stats.failed.Add(1)
		s.logf("socks5: unsupported command %d from %s", cmd, client.RemoteAddr())
		return
	}

	var destHost string
	var destPort int

	switch atyp {
	case 0x01: // IPv4
		var buf [6]byte
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			_ = sendSocks5Reply(client, 0x01)
			s.stats.failed.Add(1)
			s.logf("socks5: read ipv4 from %s failed: %v", client.RemoteAddr(), err)
			return
		}
		destHost = net.IP(buf[:4]).String()
		destPort = int(binary.BigEndian.Uint16(buf[4:6]))

	case 0x03: // Domain name
		var lenBuf [1]byte
		if _, err := io.ReadFull(client, lenBuf[:]); err != nil {
			_ = sendSocks5Reply(client, 0x01)
			s.stats.failed.Add(1)
			s.logf("socks5: read domain len from %s failed: %v", client.RemoteAddr(), err)
			return
		}
		domainLen := int(lenBuf[0])
		buf := make([]byte, domainLen+2)
		if _, err := io.ReadFull(client, buf); err != nil {
			_ = sendSocks5Reply(client, 0x01)
			s.stats.failed.Add(1)
			s.logf("socks5: read domain from %s failed: %v", client.RemoteAddr(), err)
			return
		}
		destHost = string(buf[:domainLen])
		destPort = int(binary.BigEndian.Uint16(buf[domainLen:]))

	case 0x04: // IPv6
		var buf [18]byte
		if _, err := io.ReadFull(client, buf[:]); err != nil {
			_ = sendSocks5Reply(client, 0x01)
			s.stats.failed.Add(1)
			s.logf("socks5: read ipv6 from %s failed: %v", client.RemoteAddr(), err)
			return
		}
		destHost = net.IP(buf[:16]).String()
		destPort = int(binary.BigEndian.Uint16(buf[16:18]))

	default:
		_ = sendSocks5Reply(client, 0x08) // Address type not supported
		s.stats.failed.Add(1)
		s.logf("socks5: unsupported address type %d from %s", atyp, client.RemoteAddr())
		return
	}

	targetHost := destHost
	if atyp == 0x03 && s.ResolveName != nil {
		resolved, err := s.ResolveName(ctx, destHost)
		if err != nil {
			_ = sendSocks5Reply(client, 0x04) // Host unreachable
			s.stats.failed.Add(1)
			s.logf("socks5: resolve %s failed: %v", destHost, err)
			return
		}
		targetHost = resolved
	}
	targetAddr := net.JoinHostPort(targetHost, strconv.Itoa(destPort))

	if s.Dial == nil {
		_ = sendSocks5Reply(client, 0x01)
		s.stats.failed.Add(1)
		s.logf("socks5: dialer is nil")
		return
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, handshakeTimeout)
	dest, err := s.Dial(dialCtx, "tcp", targetAddr)
	dialCancel()
	if err != nil {
		rep := socks5ErrToRep(err)
		_ = sendSocks5Reply(client, rep)
		s.stats.failed.Add(1)
		s.logf("socks5: dial %s failed: %v", targetAddr, err)
		return
	}
	defer dest.Close()
	s.trackConn(dest)
	defer s.untrackConn(dest)

	if err := sendSocks5Reply(client, 0x00); err != nil {
		s.stats.failed.Add(1)
		s.logf("socks5: write success reply to %s failed: %v", client.RemoteAddr(), err)
		return
	}

	_ = client.SetDeadline(time.Time{})

	up, down := s.relay(client, dest)
	s.logf("socks5: %s -> %s: ok (up=%d down=%d)", client.RemoteAddr(), targetAddr, up, down)
}

func (s *Server) handleHTTPConnect(ctx context.Context, client net.Conn, firstByte byte) {
	r := io.MultiReader(bytes.NewReader([]byte{firstByte}), client)
	br := bufio.NewReader(r)

	reqLine, err := br.ReadString('\n')
	if err != nil {
		s.stats.failed.Add(1)
		s.logf("http: read request line from %s failed: %v", client.RemoteAddr(), err)
		return
	}

	// Discard headers until CRLFCRLF
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			s.stats.failed.Add(1)
			s.logf("http: read headers from %s failed: %v", client.RemoteAddr(), err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
	}

	reqLine = strings.TrimRight(reqLine, "\r\n")
	fields := strings.Fields(reqLine)
	if len(fields) < 2 || strings.ToUpper(fields[0]) != "CONNECT" {
		_, _ = client.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		s.stats.failed.Add(1)
		s.logf("http: unsupported method from %s: %s", client.RemoteAddr(), reqLine)
		return
	}

	target := fields[1]
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		if !strings.Contains(target, ":") {
			host = target
			portStr = "80"
		} else {
			_, _ = client.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			s.stats.failed.Add(1)
			s.logf("http: invalid target from %s: %s (%v)", client.RemoteAddr(), target, err)
			return
		}
	}

	targetHost := host
	if net.ParseIP(host) == nil && s.ResolveName != nil {
		resolved, err := s.ResolveName(ctx, host)
		if err != nil {
			_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			s.stats.failed.Add(1)
			s.logf("http: resolve %s failed: %v", host, err)
			return
		}
		targetHost = resolved
	}
	targetAddr := net.JoinHostPort(targetHost, portStr)

	if s.Dial == nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		s.stats.failed.Add(1)
		s.logf("http: dialer is nil")
		return
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, handshakeTimeout)
	dest, err := s.Dial(dialCtx, "tcp", targetAddr)
	dialCancel()
	if err != nil {
		_, _ = client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		s.stats.failed.Add(1)
		s.logf("http: dial %s failed: %v", targetAddr, err)
		return
	}
	defer dest.Close()
	s.trackConn(dest)
	defer s.untrackConn(dest)

	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		s.stats.failed.Add(1)
		s.logf("http: write 200 response to %s failed: %v", client.RemoteAddr(), err)
		return
	}

	_ = client.SetDeadline(time.Time{})

	wrappedClient := &bufferedConn{
		Conn: client,
		r:    br,
	}

	up, down := s.relay(wrappedClient, dest)
	s.logf("http: %s -> %s: ok (up=%d down=%d)", client.RemoteAddr(), targetAddr, up, down)
}

func (s *Server) relay(client, dest net.Conn) (int64, int64) {
	var up, down int64
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, err := io.Copy(dest, &countingReader{r: client, n: &up, live: &s.stats.up})
		if err == nil {
			if cw, ok := dest.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			} else {
				_ = dest.Close()
			}
		} else {
			_ = dest.Close()
		}
	}()

	go func() {
		defer wg.Done()
		_, err := io.Copy(client, &countingReader{r: dest, n: &down, live: &s.stats.down})
		if err == nil {
			if cw, ok := client.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			} else {
				_ = client.Close()
			}
		} else {
			_ = client.Close()
		}
	}()

	wg.Wait()
	return atomic.LoadInt64(&up), atomic.LoadInt64(&down)
}

// countingReader keeps the byte counters moving during a transfer instead of
// only when each direction finishes.
type countingReader struct {
	r    io.Reader
	n    *int64
	live *atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		atomic.AddInt64(c.n, int64(n))
		c.live.Add(int64(n))
	}
	return n, err
}

func sendSocks5Reply(w io.Writer, rep byte) error {
	_, err := w.Write([]byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func socks5ErrToRep(err error) byte {
	if errors.Is(err, context.DeadlineExceeded) {
		return 0x04 // Host unreachable
	}
	var sysErr syscall.Errno
	if errors.As(err, &sysErr) {
		switch sysErr {
		case syscall.ECONNREFUSED:
			return 0x05 // Connection refused
		case syscall.ENETUNREACH:
			return 0x03 // Network unreachable
		case syscall.EHOSTUNREACH:
			return 0x04 // Host unreachable
		}
	}
	var netErr *net.OpError
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return 0x04 // Host unreachable
		}
		if errors.As(netErr.Err, &sysErr) {
			switch sysErr {
			case syscall.ECONNREFUSED:
				return 0x05
			case syscall.ENETUNREACH:
				return 0x03
			case syscall.EHOSTUNREACH:
				return 0x04
			}
		}
	}
	return 0x01 // General failure
}

type bufferedConn struct {
	net.Conn
	r io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *bufferedConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

// Stats returns a snapshot of counters.
func (s *Server) Stats() Stats {
	return Stats{
		Active:    s.stats.active.Load(),
		Total:     s.stats.total.Load(),
		Failed:    s.stats.failed.Load(),
		BytesUp:   s.stats.up.Load(),
		BytesDown: s.stats.down.Load(),
	}
}

// handshakeTimeout bounds the client handshake so a stalled peer cannot pin a
// goroutine forever.
const handshakeTimeout = 30 * time.Second

func (s *Server) logf(format string, args ...any) {
	if s.Logf != nil {
		s.Logf(format, args...)
	}
}
