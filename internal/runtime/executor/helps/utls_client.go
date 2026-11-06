package helps

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	"golang.org/x/net/http2"
	"golang.org/x/net/proxy"
)

// utlsDialTimeout bounds proxy CONNECT plus the TLS handshake for one shared connection.
const utlsDialTimeout = 30 * time.Second

// One HTTP/2 transport per proxy URL for the whole process, so requests share
// connections instead of leaving one idle tunnel per request. Proxy URLs come
// from config, so the map is not evicted.
var (
	sharedUtlsMu         sync.Mutex
	sharedUtlsTransports = map[string]*http2.Transport{}
	// utlsTestRootCAs is a test hook guarded by sharedUtlsMu; nil means the system roots.
	utlsTestRootCAs *x509.CertPool
)

// UtlsTransport returns the process-wide Chrome-fingerprinted HTTP/2 transport for
// proxyURL ("" dials directly). An invalid proxy URL yields a transport that fails every request.
func UtlsTransport(proxyURL string) http.RoundTripper {
	rt, err := sharedUtlsTransport(proxyURL)
	if err != nil {
		return proxyutil.FailingTransport(err)
	}
	return rt
}

func sharedUtlsTransport(proxyURL string) (*http2.Transport, error) {
	sharedUtlsMu.Lock()
	defer sharedUtlsMu.Unlock()
	if rt, ok := sharedUtlsTransports[proxyURL]; ok {
		return rt, nil
	}
	dialer, err := utlsDialer(proxyURL)
	if err != nil {
		return nil, err
	}
	pool := &utlsConnPool{
		dialer:  dialer,
		rootCAs: utlsTestRootCAs,
		conns:   map[string][]*http2.ClientConn{},
		dialing: map[string]*utlsDial{},
	}
	// No idle or ping timeouts: AGENTS.md forbids timeouts after a connection is established.
	rt := &http2.Transport{ConnPool: pool}
	pool.h2 = rt
	sharedUtlsTransports[proxyURL] = rt
	return rt, nil
}

func utlsDialer(proxyURL string) (proxy.ContextDialer, error) {
	if proxyURL == "" {
		return proxy.Direct, nil
	}
	dialer, _, err := proxyutil.BuildDialer(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("utls: invalid proxy %s: %w", proxyutil.Redact(proxyURL), err)
	}
	contextDialer, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("utls: proxy %s has no cancellable dialer (%T)", proxyutil.Redact(proxyURL), dialer)
	}
	return contextDialer, nil
}

// utlsConnPool is an http2.ClientConnPool that dials once per address and lets
// each waiting request give up when its own context ends.
type utlsConnPool struct {
	h2      *http2.Transport
	dialer  proxy.ContextDialer
	rootCAs *x509.CertPool
	mu      sync.Mutex
	conns   map[string][]*http2.ClientConn
	dialing map[string]*utlsDial
}

type utlsDial struct {
	done chan struct{}
	cc   *http2.ClientConn
	err  error
}

func (p *utlsConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	for {
		p.mu.Lock()
		for _, cc := range p.conns[addr] {
			if cc.ReserveNewRequest() {
				p.mu.Unlock()
				return cc, nil
			}
		}
		d, ok := p.dialing[addr]
		if !ok {
			d = &utlsDial{done: make(chan struct{})}
			p.dialing[addr] = d
			go p.dial(d, addr)
		}
		p.mu.Unlock()

		select {
		case <-d.done:
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
		if d.err != nil {
			return nil, d.err
		}
		if d.cc.ReserveNewRequest() {
			return d.cc, nil
		}
	}
}

func (p *utlsConnPool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, list := range p.conns {
		if i := slices.Index(list, cc); i >= 0 {
			if list = slices.Delete(list, i, i+1); len(list) == 0 {
				delete(p.conns, addr)
			} else {
				p.conns[addr] = list
			}
			return
		}
	}
}

// dial runs detached from any one request, so a cancelled first caller does not fail the others.
func (p *utlsConnPool) dial(d *utlsDial, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), utlsDialTimeout)
	defer cancel()
	conn, err := p.dialTLS(ctx, addr)
	if err == nil {
		if d.cc, err = p.h2.NewClientConn(conn); err != nil {
			_ = conn.Close()
		}
	}
	d.err = err

	p.mu.Lock()
	delete(p.dialing, addr)
	if err == nil {
		p.conns[addr] = append(p.conns[addr], d.cc)
	}
	p.mu.Unlock()
	close(d.done)
}

func (p *utlsConnPool) dialTLS(ctx context.Context, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	conn, err := p.dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn := tls.UClient(conn, &tls.Config{ServerName: host, RootCAs: p.rootCAs}, tls.HelloChrome_Auto)
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto != http2.NextProtoTLS {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("utls: %s negotiated ALPN %q, want %q", addr, proto, http2.NextProtoTLS)
	}
	return tlsConn, nil
}

// utlsProtectedHosts contains the hosts that should use utls Chrome TLS fingerprint
// to bypass Cloudflare's TLS fingerprinting.
var utlsProtectedHosts = map[string]struct{}{
	"api.anthropic.com": {},
	"chatgpt.com":       {},
}

// fallbackRoundTripper uses utls for protected HTTPS hosts and falls back to
// standard transport for all other requests.
type fallbackRoundTripper struct {
	utls     http.RoundTripper
	fallback http.RoundTripper
}

func (f *fallbackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" {
		if _, ok := utlsProtectedHosts[strings.ToLower(req.URL.Hostname())]; ok {
			return f.utls.RoundTrip(req)
		}
	}
	return f.fallback.RoundTrip(req)
}

// NewUtlsHTTPClient creates an HTTP client using utls Chrome TLS fingerprint.
// Use this for provider requests that need a Chrome-like TLS fingerprint.
// Falls back to standard transport for non-HTTPS requests.
func NewUtlsHTTPClient(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, timeout time.Duration) *http.Client {
	var proxyURL string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	var ctxRoundTripper http.RoundTripper
	if ctx != nil {
		ctxRoundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}

	utlsRT := UtlsTransport(proxyURL)
	var standardTransport http.RoundTripper = http.DefaultTransport
	if proxyURL != "" {
		standardTransport = proxyTransport(proxyURL)
	} else if ctxRoundTripper != nil {
		utlsRT = ctxRoundTripper
		standardTransport = ctxRoundTripper
	}

	client := &http.Client{
		Transport: &fallbackRoundTripper{
			utls:     utlsRT,
			fallback: standardTransport,
		},
	}
	if timeout > 0 {
		client.Timeout = timeout
	}
	return client
}
