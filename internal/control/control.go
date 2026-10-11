// Package control exposes a running relay to a separate UI process.
//
// The relay is meant to run as a resident service; the TUI is only ever a
// client. They talk over a tiny HTTP API carried on a Unix socket (or TCP),
// whose methods mirror the tui.Service interface exactly. That keeps the
// service headless and restartable while still letting the UI drive switching.
package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"ipvrelay/internal/tui"
)

// Listen opens the control endpoint. "unix:path" (or "unix://path") binds a
// Unix socket; anything else is treated as a TCP host:port.
func Listen(addr string) (net.Listener, error) {
	network, target, err := splitAddr(addr)
	if err != nil {
		return nil, err
	}
	if network == "unix" {
		// Drop a socket left behind by a previous run.
		_ = os.Remove(target)
	}
	return net.Listen(network, target)
}

// Serve serves the control API on ln until ctx is cancelled or the listener
// closes. It never returns a "server closed" error.
func Serve(ctx context.Context, ln net.Listener, svc tui.Service, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/rows", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, svc.Rows())
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, svc.Status())
	})
	mux.HandleFunc("/switch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			Hostname string `json:"hostname"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil || req.Hostname == "" {
			http.Error(w, "hostname required", http.StatusBadRequest)
			return
		}
		if err := svc.Switch(req.Hostname); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{Handler: mux}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	logf("control endpoint on %s", ln.Addr())

	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Client is a tui.Service backed by a remote control endpoint. It is used by
// the TUI in --connect mode.
type Client struct {
	hc   *http.Client
	base string
}

var _ tui.Service = (*Client)(nil)

// Dial builds a client for the given address ("unix:path" or host:port).
func Dial(addr string) (*Client, error) {
	network, target, err := splitAddr(addr)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{}
	base := "http://" + target
	if network == "unix" {
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", target)
		}
		base = "http://ipvrelay"
	}
	return &Client{hc: &http.Client{Transport: tr, Timeout: 30 * time.Second}, base: base}, nil
}

// Rows implements tui.Service.
func (c *Client) Rows() []tui.Row {
	var rows []tui.Row
	_ = c.get("/rows", &rows)
	return rows
}

// Status implements tui.Service. A dead endpoint surfaces as LastError so the
// UI shows why it is empty instead of silently.
func (c *Client) Status() tui.Status {
	var st tui.Status
	if err := c.get("/status", &st); err != nil {
		st.LastError = err.Error()
	}
	return st
}

// Switch implements tui.Service.
func (c *Client) Switch(hostname string) error {
	body, _ := json.Marshal(map[string]string{"hostname": hostname})
	resp, err := c.hc.Post(c.base+"/switch", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("control: %s", strings.TrimSpace(string(msg)))
	}
	return nil
}

func (c *Client) get(path string, v any) error {
	resp, err := c.hc.Get(c.base + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
		return fmt.Errorf("control: %s: %s", path, strings.TrimSpace(string(msg)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func splitAddr(addr string) (network, target string, err error) {
	switch {
	case strings.HasPrefix(addr, "unix://"):
		return "unix", strings.TrimPrefix(addr, "unix://"), nil
	case strings.HasPrefix(addr, "unix:"):
		return "unix", strings.TrimPrefix(addr, "unix:"), nil
	case strings.HasPrefix(addr, "tcp://"):
		return "tcp", strings.TrimPrefix(addr, "tcp://"), nil
	case addr == "":
		return "", "", errors.New("control: empty address")
	default:
		return "tcp", addr, nil
	}
}
