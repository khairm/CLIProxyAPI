package helps

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// One HTTP/2 transport per proxy for the whole process, so requests share connections
// instead of leaving one idle tunnel per request. Proxy URLs come from config, so the map is not evicted.
var (
	sharedUtlsMu         sync.Mutex
	sharedUtlsTransports = map[string]*utlsRoundTripper{}
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

func sharedUtlsTransport(proxyURL string) (*utlsRoundTripper, error) {
	key, err := proxyPoolKey(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("utls: invalid proxy %s: %w", proxyutil.Redact(proxyURL), err)
	}
	sharedUtlsMu.Lock()
	defer sharedUtlsMu.Unlock()
	if rt, ok := sharedUtlsTransports[key]; ok {
		return rt, nil
	}
	dialer, err := utlsDialer(proxyURL)
	if err != nil {
		return nil, err
	}
	pool := &utlsConnPool{
		dialer:  dialer,
		rootCAs: utlsTestRootCAs,
		conns:   map[string][]*utlsPooledConn{},
		dialing: map[string]*utlsDial{},
	}
	// No idle or ping timeouts: AGENTS.md forbids timeouts after a connection is established.
	h2 := &http2.Transport{ConnPool: pool}
	pool.h2 = h2
	rt := &utlsRoundTripper{h2: h2, pool: pool}
	sharedUtlsTransports[key] = rt
	return rt, nil
}

// proxyPoolKey names the pool for a proxy setting: "direct" for no proxy, otherwise the
// proxy URL without path or case differences, so equivalent settings share one pool.
func proxyPoolKey(raw string) (string, error) {
	setting, err := proxyutil.Parse(raw)
	if err != nil {
		return "", err
	}
	if setting.Mode != proxyutil.ModeProxy {
		return "direct", nil
	}
	key := url.URL{Scheme: setting.URL.Scheme, User: setting.URL.User, Host: strings.ToLower(setting.URL.Host)}
	return key.String(), nil
}

func utlsDialer(proxyURL string) (proxy.ContextDialer, error) {
	if strings.TrimSpace(proxyURL) == "" {
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

// utlsRoundTripper wraps the shared HTTP/2 transport with what it lacks for a long-lived
// shared connection: closing the body when no connection was obtained, dropping a
// connection that has gone silent, and one replay of a safe request after an abrupt close.
type utlsRoundTripper struct {
	h2   *http2.Transport
	pool *utlsConnPool
}

type utlsAttemptKey struct{}

// utlsAttempt records the connection the pool handed to one request attempt.
type utlsAttempt struct {
	conn        *utlsPooledConn
	readAtStart uint64
}

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	for replayed := false; ; replayed = true {
		attempt := &utlsAttempt{}
		resp, err := t.h2.RoundTrip(req.WithContext(context.WithValue(req.Context(), utlsAttemptKey{}, attempt)))
		if err == nil {
			return resp, nil
		}
		if attempt.conn == nil {
			// No connection was obtained, so http2 never took ownership of the body.
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, err
		}
		if req.Context().Err() != nil {
			t.pool.dropIfSilent(attempt)
			return nil, err
		}
		if replayed || !isAbruptClose(err) {
			return nil, err
		}
		next, ok := replayableRequest(req)
		if !ok {
			return nil, err
		}
		req = next
	}
}

// isAbruptClose reports a connection that ended without a GOAWAY before the response headers.
func isAbruptClose(err error) bool {
	return errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

// replayableRequest returns a fresh copy of req when it is safe to send again: an idempotent
// method (or an idempotency key, as net/http allows) and a body that can be rewound.
func replayableRequest(req *http.Request) (*http.Request, bool) {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		if req.Header.Get("Idempotency-Key") == "" && req.Header.Get("X-Idempotency-Key") == "" {
			return nil, false
		}
	}
	next := req.Clone(req.Context())
	if req.Body == nil || req.Body == http.NoBody {
		return next, true
	}
	if req.GetBody == nil {
		return nil, false
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, false
	}
	next.Body = body
	return next, true
}

// utlsConnPool is an http2.ClientConnPool that dials once per address and lets
// each waiting request give up when its own context ends.
type utlsConnPool struct {
	h2      *http2.Transport
	dialer  proxy.ContextDialer
	rootCAs *x509.CertPool
	mu      sync.Mutex
	conns   map[string][]*utlsPooledConn
	dialing map[string]*utlsDial
}

// utlsPooledConn is a shared connection plus a count of the bytes it has received,
// which tells a silent (dead) tunnel apart from a slow but healthy one.
type utlsPooledConn struct {
	cc   *http2.ClientConn
	read atomic.Uint64
}

type countingConn struct {
	net.Conn
	read *atomic.Uint64
}

func (c countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.read.Add(uint64(n))
	return n, err
}

type utlsDial struct {
	done chan struct{}
	conn *utlsPooledConn
	err  error
}

func (p *utlsConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	attempt, _ := req.Context().Value(utlsAttemptKey{}).(*utlsAttempt)
	if attempt != nil {
		attempt.conn = nil
	}
	conn, err := p.reserve(req, addr)
	if err != nil {
		return nil, err
	}
	if attempt != nil {
		attempt.conn = conn
		attempt.readAtStart = conn.read.Load()
	}
	return conn.cc, nil
}

func (p *utlsConnPool) reserve(req *http.Request, addr string) (*utlsPooledConn, error) {
	for {
		p.mu.Lock()
		for _, conn := range p.conns[addr] {
			if conn.cc.ReserveNewRequest() {
				p.mu.Unlock()
				return conn, nil
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
		if d.conn.cc.ReserveNewRequest() {
			return d.conn, nil
		}
	}
}

func (p *utlsConnPool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for addr, list := range p.conns {
		if i := slices.IndexFunc(list, func(conn *utlsPooledConn) bool { return conn.cc == cc }); i >= 0 {
			if list = slices.Delete(list, i, i+1); len(list) == 0 {
				delete(p.conns, addr)
			} else {
				p.conns[addr] = list
			}
			return
		}
	}
}

// dropIfSilent retires the attempt's connection when the request's context ended and the
// connection received nothing at all meanwhile: the tunnel is dead, so new requests must
// dial a fresh one. Shutdown lets any other streams on it finish, then closes it.
func (p *utlsConnPool) dropIfSilent(attempt *utlsAttempt) {
	if attempt.conn.read.Load() != attempt.readAtStart {
		return
	}
	cc := attempt.conn.cc
	p.MarkDead(cc)
	go func() { _ = cc.Shutdown(context.Background()) }()
}

// dial runs detached from any one request, so a cancelled first caller does not fail the others.
func (p *utlsConnPool) dial(d *utlsDial, addr string) {
	ctx, cancel := context.WithTimeout(context.Background(), utlsDialTimeout)
	defer cancel()
	conn, err := p.dialTLS(ctx, addr)
	if err == nil {
		pooled := &utlsPooledConn{}
		if pooled.cc, err = p.h2.NewClientConn(countingConn{Conn: conn, read: &pooled.read}); err != nil {
			_ = conn.Close()
		} else {
			d.conn = pooled
		}
	}
	if err != nil {
		d.err = fmt.Errorf("utls: shared dial to %s failed: %w", addr, err)
	}

	p.mu.Lock()
	delete(p.dialing, addr)
	if err == nil {
		p.conns[addr] = append(p.conns[addr], d.conn)
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
