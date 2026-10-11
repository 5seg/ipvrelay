package relay

import (
	"context"
	"time"
)

// Assignments from the API stop passing traffic after a while even though the
// WireGuard handshake still succeeds; observed after roughly forty minutes of
// idle in testing. Recovery is automatic: a fresh key pair and assignment are
// requested for the same server and the tunnel is rebuilt.
const (
	healthInterval  = 30 * time.Second
	healthTimeout   = 8 * time.Second
	healthFailLimit = 2
	// healthProbe is a plain IP so the check never depends on DNS.
	healthProbe = "1.1.1.1:443"
)

// healthLoop watches the tunnel and rebuilds it when it stops passing traffic.
func (r *Relay) healthLoop(ctx context.Context) {
	ticker := time.NewTicker(healthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		r.mu.RLock()
		current := r.current
		busy := r.switching
		r.mu.RUnlock()
		if current == "" || busy {
			continue
		}

		if err := r.probeTunnel(ctx); err == nil {
			r.mu.Lock()
			r.healthFails = 0
			r.mu.Unlock()
			continue
		}

		r.mu.Lock()
		r.healthFails++
		fails := r.healthFails
		r.mu.Unlock()
		r.logf("tunnel health check failed (%d/%d)", fails, healthFailLimit)

		if fails < healthFailLimit {
			continue
		}
		r.logf("renewing assignment for %s", current)
		r.recover(ctx, current)
	}
}

// probeTunnel opens a TCP connection through the tunnel and closes it again.
func (r *Relay) probeTunnel(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, healthTimeout)
	defer cancel()

	conn, err := r.be.DialContext(ctx, "tcp", healthProbe)
	if err != nil {
		return err
	}
	return conn.Close()
}

// recover rebuilds the tunnel for hostname with a brand new assignment.
func (r *Relay) recover(ctx context.Context, hostname string) {
	r.mu.Lock()
	if r.switching {
		r.mu.Unlock()
		return
	}
	r.switching = true
	r.healthFails = 0
	r.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	err := r.switchTo(ctx, hostname)
	r.mu.Lock()
	r.switching = false
	if err != nil {
		r.lastErr = err.Error()
	}
	r.mu.Unlock()
	if err != nil {
		r.logf("renewal failed: %v", err)
	}
}
