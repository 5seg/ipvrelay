// Package relay ties the pieces together: it authenticates, keeps the server
// list, probes latency, moves the tunnel between servers, and exposes the
// result to both the SOCKS5 ingress and the TUI.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"ipvrelay/internal/backend"
	"ipvrelay/internal/config"
	"ipvrelay/internal/tui"
	"ipvrelay/internal/vpnapi"
)

// exitIPURL answers with the caller's public address. It is only ever queried
// through the tunnel.
const exitIPURL = "https://api.ipify.org"

// listRefresh is how often the server list and latencies are refreshed.
const listRefresh = 30 * time.Minute

// probeRefresh re-measures latencies on a slower cadence than the list itself.
const probeRefresh = 10 * time.Minute

// Prompter asks the user for the account password on first run. main wires
// this to the terminal so the password is never persisted.
type Prompter func(ctx context.Context, email string) (string, error)

// Relay is safe for concurrent use.
type Relay struct {
	api     *vpnapi.Client
	be      backend.Backend
	prompt  Prompter
	logf    func(format string, args ...any)
	state   config.State
	statsFn func() (active, total, up, down int64)

	mu          sync.RWMutex
	servers     []vpnapi.Server
	current     string
	exitIP      string
	switching   bool
	lastErr     string
	healthFails int
	homeCountry string
	updatedAt   time.Time

	prober *prober
}

// Options configures a Relay.
type Options struct {
	API     *vpnapi.Client
	Backend backend.Backend
	Prompt  Prompter
	State   config.State
	// Stats reports ingress counters for the status line.
	Stats func() (active, total, up, down int64)
	Logf  func(format string, args ...any)
}

// New builds a Relay. Call Start to authenticate and bring the tunnel up.
func New(opts Options) *Relay {
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return &Relay{
		api:     opts.API,
		be:      opts.Backend,
		prompt:  opts.Prompt,
		state:   opts.State,
		statsFn: opts.Stats,
		logf:    logf,
	}
}

// Start authenticates, loads the server list, and configures the tunnel.
func (r *Relay) Start(ctx context.Context) error {
	if err := r.authenticate(ctx); err != nil {
		return err
	}
	if err := r.refreshServers(ctx); err != nil {
		return err
	}

	target := r.state.LastServer
	if target == "" || !r.hasServer(target) {
		if geo, err := r.api.GeoLocation(ctx); err == nil {
			r.mu.Lock()
			r.homeCountry = geo.Location.CountryCode
			r.mu.Unlock()
		} else {
			r.logf("geo lookup failed: %v", err)
		}
		target = r.bestGuess()
	}
	if target == "" {
		return errors.New("relay: no usable server in the list")
	}
	if err := r.switchTo(ctx, target); err != nil {
		return err
	}

	if p, err := newProber(); err == nil {
		r.prober = p
		go r.probeLoop(ctx)
	} else {
		r.logf("latency probing disabled: %v", err)
	}
	go r.refreshLoop(ctx)
	go r.healthLoop(ctx)
	return nil
}

// Close releases the tunnel and probe socket.
func (r *Relay) Close() error {
	err := r.prober.Close()
	if r.be != nil {
		if cerr := r.be.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

// DialContext is the proxy's Dialer: every destination leaves via the tunnel.
func (r *Relay) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return r.be.DialContext(ctx, network, address)
}

// Rows implements tui.Service.
func (r *Relay) Rows() []tui.Row {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rows := make([]tui.Row, 0, len(r.servers))
	for _, s := range r.servers {
		rows = append(rows, tui.Row{
			Hostname:  s.Hostname,
			Country:   s.CountryCode,
			City:      s.City,
			RamOnly:   s.RamOnly(),
			Virtual:   s.Virtual(),
			IPv6:      s.IPv6(),
			Load:      s.Capacity,
			LatencyMS: s.LatencyMS,
			Active:    s.Hostname == r.current,
		})
	}
	return rows
}

// Status implements tui.Service.
func (r *Relay) Status() tui.Status {
	r.mu.RLock()
	st := tui.Status{
		ConnectedHost: r.current,
		ExitIP:        r.exitIP,
		Backend:       r.be.Name(),
		Switching:     r.switching,
		LastError:     r.lastErr,
		UpdatedAt:     r.updatedAt,
	}
	r.mu.RUnlock()

	if r.statsFn != nil {
		st.Conns, _, st.BytesUp, st.BytesDown = r.statsFn()
	}
	return st
}

// Switch implements tui.Service. The handshake happens in the background so
// the UI stays responsive.
func (r *Relay) Switch(hostname string) error {
	r.mu.Lock()
	if r.switching {
		r.mu.Unlock()
		return errors.New("relay: a switch is already in progress")
	}
	if !r.hasServerLocked(hostname) {
		r.mu.Unlock()
		return fmt.Errorf("relay: unknown server %q", hostname)
	}
	r.switching = true
	r.lastErr = ""
	r.mu.Unlock()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if err := r.switchTo(ctx, hostname); err != nil {
			r.logf("switch to %s failed: %v", hostname, err)
			r.mu.Lock()
			r.lastErr = err.Error()
			r.switching = false
			r.mu.Unlock()
			return
		}
		r.mu.Lock()
		r.switching = false
		r.mu.Unlock()
	}()
	return nil
}

// switchTo performs one server change: fresh key pair, new assignment, new
// tunnel configuration, then confirm the exit address.
func (r *Relay) switchTo(ctx context.Context, hostname string) error {
	kp, err := generateKeyPair()
	if err != nil {
		return err
	}
	start := time.Now()
	cfg, err := r.api.WireGuardConfig(ctx, hostname, kp.Public)
	if err != nil {
		return fmt.Errorf("relay: assignment for %s: %w", hostname, err)
	}
	cfg.PrivateKey = kp.Private

	if err := r.be.Configure(ctx, cfg); err != nil {
		return fmt.Errorf("relay: configure tunnel: %w", err)
	}
	// The first packet after a configuration change is dropped while the
	// handshake completes, which would make the DNS lookup below fail.
	if err := r.waitReady(ctx); err != nil {
		return err
	}

	r.mu.Lock()
	r.current = hostname
	r.exitIP = ""
	r.updatedAt = time.Now()
	r.mu.Unlock()

	r.state.LastServer = hostname
	if err := config.Save(r.state); err != nil {
		r.logf("state save failed: %v", err)
	}

	exit, err := r.verifyExit(ctx)
	if err != nil {
		// The tunnel is up even if verification failed; report and continue.
		r.logf("exit check failed: %v", err)
	} else {
		r.mu.Lock()
		r.exitIP = exit
		r.mu.Unlock()
		r.logf("switched to %s (exit %s) in %s", hostname, exit, time.Since(start).Round(time.Millisecond))
	}
	return nil
}

// waitReady blocks until the tunnel carries traffic, so callers never race the
// handshake.
func (r *Relay) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(20 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempt, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := r.be.DialContext(attempt, "tcp", healthProbe)
		cancel()
		if err == nil {
			conn.Close()
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return fmt.Errorf("relay: tunnel did not become ready: %w", lastErr)
}

// verifyExit fetches the public address through the tunnel.
func (r *Relay) verifyExit(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext:       r.DialContext,
			DisableKeepAlives: true,
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, exitIPURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

// authenticate reuses a stored token when possible and only asks for the
// password when the session cannot be restored.
func (r *Relay) authenticate(ctx context.Context) error {
	s := r.state
	if s.AccessToken != "" && time.Now().Before(s.ExpiresAt.Add(-time.Minute)) {
		r.api.SetToken(s.AccessToken)
		r.logf("using stored session for %s", s.Email)
		return nil
	}
	if s.RefreshToken != "" {
		tokens, err := r.api.Refresh(ctx, s.RefreshToken)
		if err == nil {
			return r.storeTokens(tokens)
		}
		r.logf("refresh failed (%v), signing in again", err)
	}
	if r.prompt == nil {
		return errors.New("relay: session expired and no way to ask for the password")
	}
	password, err := r.prompt(ctx, s.Email)
	if err != nil {
		return err
	}
	tokens, err := r.api.Login(ctx, s.Email, password)
	if err != nil {
		return err
	}
	return r.storeTokens(tokens)
}

func (r *Relay) storeTokens(t vpnapi.Tokens) error {
	r.api.SetToken(t.AccessToken)
	r.state.AccessToken = t.AccessToken
	r.state.RefreshToken = t.RefreshToken
	r.state.ExpiresAt = t.ExpiresAt
	if t.Email != "" {
		r.state.Email = t.Email
	}
	// The password is deliberately not part of the state.
	return config.Save(r.state)
}

func (r *Relay) refreshServers(ctx context.Context) error {
	servers, err := r.api.Servers(ctx)
	if err != nil {
		return fmt.Errorf("relay: server list: %w", err)
	}
	for i := range servers {
		servers[i].LatencyMS = -1
	}
	r.mu.Lock()
	previous := r.servers
	r.servers = servers
	r.updatedAt = time.Now()
	r.mu.Unlock()

	r.mergeLatency(previous, servers)
	r.logf("loaded %d servers", len(servers))
	return nil
}

// mergeLatency carries measured latencies across a list refresh.
func (r *Relay) mergeLatency(old, next []vpnapi.Server) {
	if len(old) == 0 {
		return
	}
	known := make(map[string]int, len(old))
	for _, s := range old {
		if s.LatencyMS >= 0 {
			known[s.Hostname] = s.LatencyMS
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.servers {
		if v, ok := known[r.servers[i].Hostname]; ok {
			r.servers[i].LatencyMS = v
		}
	}
}

// probeLoop measures every candidate periodically.
func (r *Relay) probeLoop(ctx context.Context) {
	ticker := time.NewTicker(jittered(probeRefresh))
	defer ticker.Stop()
	for {
		r.mu.RLock()
		targets := append([]vpnapi.Server(nil), r.servers...)
		r.mu.RUnlock()

		r.prober.probeAll(ctx, targets, func(hostname string, rtt time.Duration) {
			r.mu.Lock()
			for i := range r.servers {
				if r.servers[i].Hostname == hostname {
					r.servers[i].LatencyMS = int(rtt.Milliseconds())
					break
				}
			}
			r.mu.Unlock()
		})

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// refreshLoop keeps the server list current.
func (r *Relay) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(listRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := r.refreshServers(ctx); err != nil {
				r.logf("server list refresh failed: %v", err)
			}
		}
	}
}

func (r *Relay) hasServer(hostname string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hasServerLocked(hostname)
}

func (r *Relay) hasServerLocked(hostname string) bool {
	for _, s := range r.servers {
		if s.Hostname == hostname {
			return true
		}
	}
	return false
}

// bestGuess is the fastest measured RAM-only server, falling back to the
// least loaded one. Used on the very first run.
func (r *Relay) bestGuess() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Prefer servers in the user's own country: the load number alone would
	// otherwise send them halfway around the world.
	pool := make([]vpnapi.Server, 0, len(r.servers))
	for _, s := range r.servers {
		if s.Maintenance {
			continue
		}
		pool = append(pool, s)
	}
	candidates := pool
	if r.homeCountry != "" {
		local := make([]vpnapi.Server, 0, 32)
		for _, s := range pool {
			if s.CountryCode == r.homeCountry {
				local = append(local, s)
			}
		}
		if len(local) > 0 {
			candidates = local
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if (a.LatencyMS >= 0) != (b.LatencyMS >= 0) {
			return a.LatencyMS >= 0
		}
		if a.LatencyMS >= 0 && a.LatencyMS != b.LatencyMS {
			return a.LatencyMS < b.LatencyMS
		}
		if a.RamOnly() != b.RamOnly() {
			return a.RamOnly()
		}
		return a.Capacity < b.Capacity
	})
	return candidates[0].Hostname
}
