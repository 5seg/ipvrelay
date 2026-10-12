// Command ipvrelay runs a local SOCKS5 proxy whose exit can be moved between
// IPVanish WireGuard servers from a terminal UI.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"ipvrelay/internal/apiproxy"
	"ipvrelay/internal/backend"
	"ipvrelay/internal/config"
	"ipvrelay/internal/control"
	"ipvrelay/internal/proxy"
	"ipvrelay/internal/relay"
	"ipvrelay/internal/tui"
	"ipvrelay/internal/vpnapi"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, "ipvrelay:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen      = flag.String("listen", "127.0.0.1:1080", "SOCKS5 listen address")
		backendName = flag.String("backend", "", "tunnel backend: kernel, userspace, or empty to auto-detect")
		iface       = flag.String("iface", "wg0", "kernel WireGuard interface name")
		email       = flag.String("email", "", "IPVanish account email (prompted when missing)")
		apiProxy    = flag.String("api-proxy", "", "route API calls through this proxy (socks5h://host:port or http://host:port)")
		controlAddr = flag.String("control", "", "control endpoint for a connecting UI (unix:path or host:port; default beside the state file)")
		connectAddr = flag.String("connect", "", "run the TUI against a running service instead of owning the tunnel")
		noTUI       = flag.Bool("no-tui", false, "run headless and log to stderr")
		verbose     = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	logf := func(format string, args ...any) {
		if *verbose || *noTUI {
			fmt.Fprintf(os.Stderr, "["+time.Now().Format("15:04:05")+"] "+format+"\n", args...)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Client mode: the TUI is only a view onto a service that owns the tunnel.
	// When a service is already running at the default endpoint, a plain
	// interactive run attaches to it instead of starting a second tunnel.
	connect := *connectAddr
	if connect == "" && !*noTUI && isTerminal(os.Stdin) {
		if addr := resolveControlAddr(""); addr != "" && control.Live(addr) {
			connect = addr
		}
	}
	if connect != "" {
		client, err := control.Dial(connect)
		if err != nil {
			return err
		}
		return tui.Run(ctx, client, 3*time.Second)
	}

	state, err := config.Load()
	if err != nil {
		return err
	}
	if *email != "" {
		state.Email = *email
	}
	if state.Email == "" {
		state.Email, err = promptLine("IPVanish email: ")
		if err != nil {
			return err
		}
	}
	if state.Email == "" {
		return errors.New("no account email given")
	}

	opts := []vpnapi.Option{}
	if state.APIToken != "" {
		opts = append(opts, vpnapi.WithAPIKey(state.APIToken))
	}
	if envProxy := os.Getenv("IPVRELAY_API_PROXY"); *apiProxy == "" && envProxy != "" {
		*apiProxy = envProxy
	}
	if *apiProxy != "" {
		hc, err := apiproxy.Client(*apiProxy, 30*time.Second)
		if err != nil {
			return err
		}
		opts = append(opts, vpnapi.WithHTTPClient(hc))
		logf("API traffic routed through %s", *apiProxy)
	}
	api := vpnapi.New(opts...)

	be, err := backend.Detect(ctx, backend.Options{
		Prefer: *backendName,
		Iface:  *iface,
		Logf:   logf,
	})
	if err != nil {
		return err
	}

	proxySrv := proxy.New(*listen, nil, logf)
	relaySvc := relay.New(relay.Options{
		API:     api,
		Backend: be,
		Prompt:  promptPassword,
		State:   state,
		Logf:    logf,
		Stats: func() (int64, int64, int64, int64) {
			s := proxySrv.Stats()
			return s.Active, s.Total, s.BytesUp, s.BytesDown
		},
	})
	proxySrv.Dial = relaySvc.DialContext

	if err := relaySvc.Start(ctx); err != nil {
		return err
	}
	defer relaySvc.Close()

	// Let a separate TUI process drive this service.
	if addr := resolveControlAddr(*controlAddr); addr != "" {
		if ln, err := control.Listen(addr); err != nil {
			logf("control endpoint disabled: %v", err)
		} else {
			go func() {
				if err := control.Serve(ctx, ln, relaySvc, logf); err != nil {
					logf("control endpoint stopped: %v", err)
				}
			}()
		}
	}

	errCh := make(chan error, 2)
	go func() { errCh <- proxySrv.Serve(ctx) }()

	fmt.Fprintf(os.Stderr, "ipvrelay: SOCKS5 on %s via %s backend\n", *listen, be.Name())

	if *noTUI {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		}
	}

	go func() {
		if err := <-errCh; err != nil {
			logf("proxy stopped: %v", err)
			stop()
		}
	}()
	return tui.Run(ctx, relaySvc, 3*time.Second)
}

// isTerminal reports whether f is attached to a character device (a tty).
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// resolveControlAddr picks the control endpoint: explicit flag, then env, then
// a Unix socket beside the state file (which both service and UI know).
func resolveControlAddr(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if env := os.Getenv("IPVRELAY_CONTROL"); env != "" {
		return env
	}
	if dir, err := config.Dir(); err == nil {
		return "unix:" + filepath.Join(dir, "control.sock")
	}
	return ""
}

// promptLine reads a single line from the terminal.
func promptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// promptPassword reads the account password without echoing it and without
// storing it anywhere.
func promptPassword(_ context.Context, email string) (string, error) {
	if email != "" {
		fmt.Fprintf(os.Stderr, "IPVanish password for %s: ", email)
	} else {
		fmt.Fprint(os.Stderr, "IPVanish password: ")
	}
	// stty is present on every platform we target; the fallback is a plain read.
	if _, err := exec.LookPath("stty"); err == nil {
		off := exec.Command("stty", "-echo")
		off.Stdin = os.Stdin
		if err := off.Run(); err == nil {
			defer func() {
				on := exec.Command("stty", "echo")
				on.Stdin = os.Stdin
				_ = on.Run()
				fmt.Fprintln(os.Stderr)
			}()
		}
	}
	return promptLine("")
}
