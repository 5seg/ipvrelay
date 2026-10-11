// Package vpnapi talks to IPVanish's app-facing v3 API.
//
// Everything in this package was verified against the live service. See
// DESIGN.md sections 1.3 and 1.5 for the raw evidence. Two details are easy to
// get wrong: the login call needs BOTH the X-API-Key header and the api_key
// field in the JSON body, and WireGuard public keys cannot be reused.
package vpnapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AppAPIKey is the client credential embedded in the official clients. It can
// be overridden per client with WithAPIKey.
const AppAPIKey = "619a91cf2e398a46dcc97bb961f3a23b"

// BaseURL is the primary API host. The official client rotates through several
// mirror domains (trutri.org, visualrad.org, carpetcouriers.com, kaydeolib.io)
// when the primary is blocked; the first is used here.
const BaseURL = "https://api.ipvanish.com/api/v3"

// APIVersion is the header value the official client sends.
const (
	apiVersionLogin = "3.4"
	apiVersionList  = "3.5"
	userAgent       = "IPVanish 4.3.33 (Windows)"
)

// ServerFeature is the bitmask returned as "features" for every server.
type ServerFeature uint32

const (
	FeatureNone     ServerFeature = 0
	FeatureVirtual  ServerFeature = 1  // no physical hardware in that city
	FeatureStdProto ServerFeature = 2  // standard protocol set
	FeatureRamOnly  ServerFeature = 4  // RAM-only host
	FeatureQuantum  ServerFeature = 8  // post-quantum, unused today
	FeatureIPv6     ServerFeature = 16 // IPv6 endpoints available
)

// Server is one WireGuard endpoint. LatencyMS is filled in locally by the RTT
// prober, never by the API.
type Server struct {
	Hostname    string        `json:"name"`
	City        string        `json:"city"`
	CountryCode string        `json:"country"`
	IP          string        `json:"ip_address"`
	Capacity    int           `json:"capacity"`
	Features    ServerFeature `json:"features"`
	Maintenance bool          `json:"maintenance"`

	LatencyMS int `json:"-"` // -1 means "not measured yet"
}

// RamOnly reports whether this specific server runs from RAM.
func (s Server) RamOnly() bool { return s.Features&FeatureRamOnly != 0 }

// Virtual reports whether this is a virtual location.
func (s Server) Virtual() bool { return s.Features&FeatureVirtual != 0 }

// IPv6 reports whether this server offers IPv6.
func (s Server) IPv6() bool { return s.Features&FeatureIPv6 != 0 }

// Tokens is the session returned by Login and Refresh.
type Tokens struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"-"`
	Email        string    `json:"email"`
	UID          string    `json:"uid"`
}

// wireGuardConfig is one endpoint assignment. PrivateKey is generated locally
// and never leaves the machine.
type WireGuardConfig struct {
	PrivateKey    string
	Address       string // host CIDR, e.g. "100.96.0.147/32"
	DNSServers    []string
	PeerPublicKey string
	PeerEndpoint  string // "64.145.90.18:51820"
	AllowedIPs    []string
	PortStart     int
	PortEnd       int
}

// Client is safe for concurrent use once a token has been set.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client

	mu          sync.RWMutex
	accessToken string
}

// Option customises a Client.
type Option func(*Client)

// WithBaseURL points the client at a mirror domain.
func WithBaseURL(u string) Option { return func(c *Client) { c.baseURL = u } }

// WithAPIKey overrides the embedded app credential.
func WithAPIKey(k string) Option { return func(c *Client) { c.apiKey = k } }

// WithHTTPClient routes control-plane traffic through a custom client, which
// is how the API stays reachable from hosts whose own address Cloudflare
// rejects.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New returns a Client. The token is empty until Login or SetToken is called.
func New(opts ...Option) *Client {
	c := &Client{
		apiKey:  AppAPIKey,
		baseURL: BaseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SetToken installs an existing access token.
func (c *Client) SetToken(access string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.accessToken = access
}

// SetHTTPClient swaps the transport used for control-plane calls. The relay
// uses it to move API traffic onto the tunnel once one is up, which is the only
// way to reach the API from hosts Cloudflare rejects.
func (c *Client) SetHTTPClient(h *http.Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.http = h
}

func (c *Client) token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.accessToken
}

func (c *Client) newRequest(ctx context.Context, method, path, version string, body any) (*http.Request, error) {
	baseURL := strings.TrimRight(c.baseURL, "/")
	cleanPath := strings.TrimLeft(path, "/")
	reqURL := baseURL + "/" + cleanPath

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("vpnapi: marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("vpnapi: new request: %w", err)
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("X-API-Key", c.apiKey)
	if version != "" {
		req.Header.Set("X-API-Version", version)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	if tok := c.token(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	return req, nil
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vpnapi: do request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vpnapi: read response: %w", err)
	}

	var apiErr apiError
	if err := json.Unmarshal(bodyBytes, &apiErr); err == nil {
		if apiErr.Code != 0 || apiErr.Reason != "" {
			return nil, apiErr
		}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, apiError{
			Code:   resp.StatusCode,
			Reason: strings.TrimSpace(string(bodyBytes)),
		}
	}

	return bodyBytes, nil
}

// Login exchanges credentials for a session. It must send the X-API-Key header
// AND a JSON body containing client, os, username, password and api_key.
func (c *Client) Login(ctx context.Context, username, password string) (Tokens, error) {
	reqBody := struct {
		Client   string `json:"client"`
		OS       string `json:"os"`
		Username string `json:"username"`
		Password string `json:"password"`
		APIKey   string `json:"api_key"`
	}{
		Client:   "IPVanish 4.3.33",
		OS:       "Windows",
		Username: username,
		Password: password,
		APIKey:   c.apiKey,
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/login", apiVersionLogin, reqBody)
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Del("Authorization")

	bodyBytes, err := c.do(req)
	if err != nil {
		return Tokens{}, err
	}

	var raw struct {
		AccessToken       string `json:"access_token"`
		RefreshToken      string `json:"refresh_token"`
		AccessExpireEpoch int64  `json:"access_expire_epoch"`
		Email             string `json:"email"`
		UID               string `json:"uid"`
	}
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return Tokens{}, fmt.Errorf("vpnapi: decode login response: %w", err)
	}

	var expiresAt time.Time
	if raw.AccessExpireEpoch > 0 {
		expiresAt = time.Unix(raw.AccessExpireEpoch, 0)
	} else {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	tokens := Tokens{
		AccessToken:  raw.AccessToken,
		RefreshToken: raw.RefreshToken,
		ExpiresAt:    expiresAt,
		Email:        raw.Email,
		UID:          raw.UID,
	}

	c.SetToken(tokens.AccessToken)
	return tokens, nil
}

// Refresh gets a new access token from a refresh token.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	reqBody := struct {
		RefreshToken string `json:"refresh_token"`
	}{
		RefreshToken: refreshToken,
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/login", apiVersionLogin, reqBody)
	if err != nil {
		return Tokens{}, err
	}

	bodyBytes, err := c.do(req)
	if err != nil {
		return Tokens{}, err
	}

	var raw struct {
		AccessToken       string `json:"access_token"`
		RefreshToken      string `json:"refresh_token"`
		AccessExpireEpoch int64  `json:"access_expire_epoch"`
		Email             string `json:"email"`
		UID               string `json:"uid"`
	}
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return Tokens{}, fmt.Errorf("vpnapi: decode refresh response: %w", err)
	}

	var expiresAt time.Time
	if raw.AccessExpireEpoch > 0 {
		expiresAt = time.Unix(raw.AccessExpireEpoch, 0)
	} else {
		expiresAt = time.Now().Add(1 * time.Hour)
	}

	tok := raw.RefreshToken
	if tok == "" {
		tok = refreshToken
	}

	tokens := Tokens{
		AccessToken:  raw.AccessToken,
		RefreshToken: tok,
		ExpiresAt:    expiresAt,
		Email:        raw.Email,
		UID:          raw.UID,
	}

	c.SetToken(tokens.AccessToken)
	return tokens, nil
}

// Servers returns the full server list, including feature bits and load.
func (c *Client) Servers(ctx context.Context) ([]Server, error) {
	req, err := c.newRequest(ctx, http.MethodGet, "/servers?simple_type=true", apiVersionList, nil)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := c.do(req)
	if err != nil {
		return nil, err
	}

	var raw serversResponse
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return nil, fmt.Errorf("vpnapi: decode servers response: %w", err)
	}

	for i := range raw.Servers {
		raw.Servers[i].LatencyMS = -1
	}

	return raw.Servers, nil
}

// WireGuardConfig registers publicKey for hostname and returns the assignment.
// publicKey must be a fresh, previously unused base64 key.
func (c *Client) WireGuardConfig(ctx context.Context, hostname, publicKey string) (WireGuardConfig, error) {
	reqBody := struct {
		Server    string `json:"server"`
		PublicKey string `json:"publickey"`
		APIKey    string `json:"api_key"`
		UUID      string `json:"UUID"`
		AllowLAN  int    `json:"allowlan"`
	}{
		Server:    hostname,
		PublicKey: publicKey,
		APIKey:    c.apiKey,
		UUID:      newUUID(),
		AllowLAN:  0,
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/wireguard", apiVersionLogin, reqBody)
	if err != nil {
		return WireGuardConfig{}, err
	}

	bodyBytes, err := c.do(req)
	if err != nil {
		return WireGuardConfig{}, err
	}

	var raw struct {
		Config struct {
			Interface struct {
				Address string   `json:"Address"`
				DNS     []string `json:"DNS"`
			} `json:"Interface"`
			Peer struct {
				AllowedIPs []string `json:"AllowedIPs"`
				Endpoint   string   `json:"Endpoint"`
				PublicKey  string   `json:"PublicKey"`
			} `json:"Peer"`
		} `json:"config"`
		Settings struct {
			PortStart int `json:"port_start"`
			PortEnd   int `json:"port_end"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(bodyBytes, &raw); err != nil {
		return WireGuardConfig{}, fmt.Errorf("vpnapi: decode wireguard response: %w", err)
	}

	dns := raw.Config.Interface.DNS
	if dns == nil {
		dns = []string{}
	}
	allowedIPs := raw.Config.Peer.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = []string{}
	}

	cfg := WireGuardConfig{
		Address:       raw.Config.Interface.Address,
		DNSServers:    dns,
		PeerPublicKey: raw.Config.Peer.PublicKey,
		PeerEndpoint:  raw.Config.Peer.Endpoint,
		AllowedIPs:    allowedIPs,
		PortStart:     raw.Settings.PortStart,
		PortEnd:       raw.Settings.PortEnd,
	}
	return cfg, nil
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// ---- decoding helpers used by the implementation ----

type serversResponse struct {
	Servers []Server `json:"servers"`
}

// apiError is the {"code":N,"reason":"..."} error shape.
type apiError struct {
	Code   int    `json:"code"`
	Reason string `json:"reason"`
	Detail string `json:"detail"`
}

func (e apiError) Error() string {
	if e.Reason == "" {
		return "vpnapi: error " + strconv.Itoa(e.Code)
	}
	return fmt.Sprintf("vpnapi: %s (code %d)", e.Reason, e.Code)
}

var _ = json.Marshal
