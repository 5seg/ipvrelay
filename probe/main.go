package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type cfg struct {
	priv, address, dns, peerPub, allowedIPs, endpoint string
}

func b64hex(s string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		panic("bad base64 key: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func parseConf(path string) cfg {
	var c cfg
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "PrivateKey":
			c.priv = b64hex(v)
		case "Address":
			c.address = v
		case "DNS":
			c.dns = v
		case "PublicKey":
			c.peerPub = b64hex(v)
		case "AllowedIPs":
			c.allowedIPs = v
		case "Endpoint":
			c.endpoint = v
		}
	}
	return c
}

func main() {
	confPath := flag.String("conf", "", "wg-quick config")
	endpoint := flag.String("endpoint", "", "override endpoint host:port")
	target := flag.String("target", "http://api.ipify.org/", "http URL to fetch through tunnel")
	verbose := flag.Bool("v", false, "verbose wg logging")
	bench := flag.Int("bench", 0, "download N bytes from cloudflare speedtest through tunnel")
	flag.Parse()

	c := parseConf(*confPath)
	if *endpoint != "" {
		c.endpoint = *endpoint
	}

	addr, err := netip.ParsePrefix(strings.Split(c.address, ",")[0])
	if err != nil {
		panic(err)
	}
	var dnsIPs []netip.Addr
	for _, d := range strings.Split(c.dns, ",") {
		if a, err := netip.ParseAddr(strings.TrimSpace(d)); err == nil {
			dnsIPs = append(dnsIPs, a)
		}
	}

	tunDev, tnet, err := netstack.CreateNetTUN([]netip.Addr{addr.Addr()}, dnsIPs, 1420)
	if err != nil {
		panic("netstack: " + err.Error())
	}
	lvl := device.LogLevelError
	if *verbose {
		lvl = device.LogLevelVerbose
	}
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), device.NewLogger(lvl, "wg "))
	defer dev.Close()

	ipc := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=15\n",
		c.priv, c.peerPub, c.endpoint, c.allowedIPs)
	if err := dev.IpcSet(ipc); err != nil {
		panic("ipcset: " + err.Error())
	}
	if err := dev.Up(); err != nil {
		panic("up: " + err.Error())
	}

	fmt.Printf("[*] tunnel up  local=%s dns=%v peer=%s\n", addr.Addr(), dnsIPs, c.endpoint)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// raw TCP to a well-known IP first (exercises the data path)
	t0 := time.Now()
	conn, err := tnet.DialContext(ctx, "tcp", "1.1.1.1:80")
	if err != nil {
		fmt.Println("[-] raw tcp dial 1.1.1.1:80 FAILED:", err)
		os.Exit(2)
	}
	fmt.Printf("[+] raw tcp dial 1.1.1.1:80 OK (%s)\n", time.Since(t0).Round(time.Millisecond))
	conn.Close()

	// then an HTTP request by hostname -> exercises tunnel DNS
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, address)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: tr, Timeout: 20 * time.Second}
	t1 := time.Now()
	resp, err := client.Get(*target)
	if err != nil {
		fmt.Println("[-] http get FAILED:", err)
		os.Exit(3)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	resp.Body.Close()
	fmt.Printf("[+] HTTP %s -> %d in %s: %s\n", *target, resp.StatusCode, time.Since(t1).Round(time.Millisecond), strings.TrimSpace(string(body)))

	if *bench > 0 {
		url := fmt.Sprintf("https://speed.cloudflare.com/__down?bytes=%d", *bench)
		for i := 1; i <= 2; i++ {
			c2 := &http.Client{Transport: tr, Timeout: 80 * time.Second}
			start := time.Now()
			r2, err := c2.Get(url)
			if err != nil {
				fmt.Printf("[-] bench run%d FAILED: %v\n", i, err)
				continue
			}
			n, _ := io.Copy(io.Discard, r2.Body)
			r2.Body.Close()
			d := time.Since(start)
			fmt.Printf("[+] netstack run%d: %.2f MB/s (%d bytes in %s)\n", i, float64(n)/1e6/d.Seconds(), n, d.Round(time.Millisecond))
		}
	}
}
