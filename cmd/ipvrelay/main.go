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
	"strings"
	"syscall"
	"time"

	"ipvrelay/internal/backend"
	"ipvrelay/internal/config"
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
		noTUI       = flag.Bool("no-tui", false, "run headless and log to stderr")
		verbose     = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	logf := func(format string, args ...any) {
		if *verbose || *noTUI {
			fmt.Fprintf(os.Stderr, "["+time.Now().Format("15:04:05")+"] "+format+"\n", args...)
		}
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

	api := vpnapi.New()
	if state.APIToken != "" {
		api = vpnapi.New(vpnapi.WithAPIKey(state.APIToken))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
