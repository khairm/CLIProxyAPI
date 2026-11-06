package helps

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
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

// One HTTP/2 transport per proxy and account for the whole process, so requests share
// connections instead of leaving one idle tunnel per request, and accounts never share one.
// Entries are never evicted: a removed account or replaced proxy keeps only memory, because the
// upstream closes its idle tunnel (chatgpt.com after about 6.5 minutes).
var (
	sharedUtlsMu         sync.Mutex
	sharedUtlsTransports = map[transportKey]*utlsRoundTripper{}
	// utlsTestRootCAs is a test hook guarded by sharedUtlsMu; nil means the system roots.
	utlsTestRootCAs *x509.CertPool
)

// UtlsTransport returns the process-wide Chrome-fingerprinted HTTP/2 transport for
// proxyURL ("" dials directly) used without an account, such as login flows.
// An invalid proxy URL yields a transport that fails every request.
func UtlsTransport(proxyURL string) http.RoundTripper {
	return utlsTransportFor(proxyURL, "")
}

// UtlsTransportForAuth is UtlsTransport for one account, which never shares a connection with another.
func UtlsTransportForAuth(proxyURL, authID string) http.RoundTripper {
	return utlsTransportFor(proxyURL, authID)
}

func utlsTransportFor(proxyURL, authID string) http.RoundTripper {
	rt, err := sharedUtlsTransport(proxyURL, authID)
	if err != nil {
		return proxyutil.FailingTransport(err)
	}
	return rt
}

func sharedUtlsTransport(proxyURL, authID string) (*utlsRoundTripper, error) {
	key, err := newTransportKey(proxyURL, authID)
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
	rt := &utlsRoundTripper{pool: pool}
	sharedUtlsTransports[key] = rt
	return rt, nil
}

// transportKey names a shared transport: the proxy ("direct" for none, otherwise the proxy
// URL without path or case differences) and the account ("" when there is none).
type transportKey struct {
	proxy  string
	authID string
}

func newTransportKey(proxyURL, authID string) (transportKey, error) {
	setting, err := proxyutil.Parse(proxyURL)
	if err != nil {
		return transportKey{}, err
	}
	key := transportKey{proxy: "direct", authID: authID}
	if setting.Mode == proxyutil.ModeProxy {
		normalised := url.URL{Scheme: setting.URL.Scheme, User: setting.URL.User, Host: strings.ToLower(setting.URL.Host)}
		key.proxy = normalised.String()
	}
	return key, nil
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

// utlsRoundTripper sends requests over the shared HTTP/2 connections itself, instead of through
// http2.Transport's retry loop, so it controls which requests may be sent twice: one the server
// confirmed it never processed is retried; any other is replayed at most once, and only when
// it is safe to send again. It also closes the body when no connection was obtained and drops
// a connection that has gone silent.
type utlsRoundTripper struct {
	pool *utlsConnPool
}

// maxUnprocessedRetries bounds retries of a request the server confirmed it never processed.
const maxUnprocessedRetries = 6

func (t *utlsRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != "https" {
		closeRequestBody(req)
		return nil, fmt.Errorf("utls: unsupported scheme %q", req.URL.Scheme)
	}
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(req.URL.Hostname(), port)
	replayed := false
	for retry := 0; ; retry++ {
		attempt, body := withOnceClosedBody(req)
		conn, err := t.pool.reserve(req.Context(), addr)
		if err != nil {
			body.Close()
			return nil, err
		}
		readAtStart := conn.read.Load()
		resp, err := conn.cc.RoundTrip(attempt)
		if err == nil {
			return resp, nil
		}
		body.Close()
		if req.Context().Err() != nil {
			t.pool.dropIfSilent(conn, readAtStart)
			return nil, err
		}
		switch {
		case serverDidNotProcess(err) && retry < maxUnprocessedRetries:
		case !replayed && mayHaveBeenProcessed(err) && safeToSendTwice(req):
			replayed = true
		default:
			return nil, err
		}
		if waitErr := waitBeforeRetry(req.Context(), retryBackoff(retry)); waitErr != nil {
			return nil, waitErr
		}
		next, ok := rewoundRequest(req)
		if !ok {
			return nil, err
		}
		req = next
	}
}

// retryBackoff is the wait before the retry that follows attempt retry; tests replace it.
var retryBackoff = xnetRetryBackoff

// xnetRetryBackoff is x/net's schedule: no wait before the first retry, then 1s, 2s, 4s... plus
// up to 10% jitter. It waits before a request is sent, never on an open stream.
func xnetRetryBackoff(retry int) time.Duration {
	if retry == 0 {
		return 0
	}
	backoff := float64(time.Second) * float64(uint(1)<<(uint(retry)-1))
	return time.Duration(backoff + backoff*0.1*rand.Float64())
}

func waitBeforeRetry(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// http2 does not export these errors; they are matched by text.
const (
	errTextConnUnusable  = "http2: client conn not usable"
	errTextConnGotGoAway = "http2: Transport received Server's graceful shutdown GOAWAY"
	errTextFromPeer      = "received from peer"
)

// serverDidNotProcess reports an error after which the server cannot have acted on the request:
// the connection was unusable before the stream opened, the stream was above the GOAWAY's last
// stream id, or the server refused the stream.
func serverDidNotProcess(err error) bool {
	if text := err.Error(); text == errTextConnUnusable || text == errTextConnGotGoAway {
		return true
	}
	var se http2.StreamError
	return errors.As(err, &se) && se.Code == http2.ErrCodeRefusedStream
}

// mayHaveBeenProcessed reports a failure that is often transient but leaves unknown whether the
// server acted on the request: an abrupt close before the response, or a PROTOCOL_ERROR reset
// sent by the server. A PROTOCOL_ERROR raised locally, such as on a malformed response, means
// the server already answered, so it is not one.
func mayHaveBeenProcessed(err error) bool {
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	var se http2.StreamError
	return errors.As(err, &se) && se.Code == http2.ErrCodeProtocol && se.Cause != nil && se.Cause.Error() == errTextFromPeer
}

// safeToSendTwice reports an idempotent method, or an idempotency key as net/http allows.
func safeToSendTwice(req *http.Request) bool {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	}
	return req.Header.Get("Idempotency-Key") != "" || req.Header.Get("X-Idempotency-Key") != ""
}

// rewoundRequest returns a copy of req with its body back at the start, when that is possible.
func rewoundRequest(req *http.Request) (*http.Request, bool) {
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

// onceClosedBody lets both http2 and the round tripper close an attempt's body, closing it once.
type onceClosedBody struct {
	io.ReadCloser
	once sync.Once
}

func (b *onceClosedBody) Close() error {
	var err error
	b.once.Do(func() { err = b.ReadCloser.Close() })
	return err
}

type noopCloser struct{}

func (noopCloser) Close() error { return nil }

// withOnceClosedBody returns the request to send for one attempt and the closer for its body.
func withOnceClosedBody(req *http.Request) (*http.Request, io.Closer) {
	if req.Body == nil || req.Body == http.NoBody {
		return req, noopCloser{}
	}
	body := &onceClosedBody{ReadCloser: req.Body}
	attempt := *req
	attempt.Body = body
	return &attempt, body
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
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

// GetClientConn serves http2's own use of the pool; utlsRoundTripper calls reserve directly.
func (p *utlsConnPool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	conn, err := p.reserve(req.Context(), addr)
	if err != nil {
		return nil, err
	}
	return conn.cc, nil
}

// reserve returns a shared connection with a stream reserved for one request, dialling one
// when none can take it. A request whose context has already ended reserves nothing.
func (p *utlsConnPool) reserve(ctx context.Context, addr string) (*utlsPooledConn, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if d.err != nil {
			return nil, d.err
		}
		if ctx.Err() == nil && d.conn.cc.ReserveNewRequest() {
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

// dropIfSilent retires conn when a request sent on it ended with its context and the connection
// received nothing at all meanwhile: the tunnel is dead, so new requests must dial a fresh one.
// A quick cancel on a quiet but healthy connection therefore costs one redial.
// Shutdown lets any other streams on it finish, then closes it.
func (p *utlsConnPool) dropIfSilent(conn *utlsPooledConn, readAtStart uint64) {
	if conn.read.Load() != readAtStart {
		return
	}
	p.MarkDead(conn.cc)
	go func() { _ = conn.cc.Shutdown(context.Background()) }()
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
	var proxyURL, authID string
	if auth != nil {
		proxyURL = strings.TrimSpace(auth.ProxyURL)
		authID = auth.ID
	}
	if proxyURL == "" && cfg != nil {
		proxyURL = strings.TrimSpace(cfg.ProxyURL)
	}

	var ctxRoundTripper http.RoundTripper
	if ctx != nil {
		ctxRoundTripper, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
	}

	utlsRT := utlsTransportFor(proxyURL, authID)
	var standardTransport http.RoundTripper = http.DefaultTransport
	if proxyURL != "" {
		standardTransport = proxyTransport(proxyURL, authID)
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
