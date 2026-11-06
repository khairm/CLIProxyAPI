package helps

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestMain(m *testing.M) {
	// Retries skip x/net's 1s, 2s, 4s... backoff in tests; TestRetryBackoffFollowsXNet covers it.
	retryBackoff = func(int) time.Duration { return 0 }
	os.Exit(m.Run())
}

func TestRetryBackoffFollowsXNet(t *testing.T) {
	if d := xnetRetryBackoff(0); d != 0 {
		t.Fatalf("first retry waits %v, want no wait", d)
	}
	for retry, base := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 3: 4 * time.Second, 6: 32 * time.Second} {
		if d := xnetRetryBackoff(retry); d < base || d > base+base/10 {
			t.Fatalf("retry %d waits %v, want %v plus up to 10%%", retry, d, base)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := waitBeforeRetry(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context canceled", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("a cancelled request kept waiting for its retry")
	}
}

type utlsClientRoundTripFunc func(*http.Request) (*http.Response, error)

func (f utlsClientRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestNewUtlsHTTPClientUsesContextRoundTripperForProtectedHost(t *testing.T) {
	t.Parallel()

	called := false
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", utlsClientRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.URL.Hostname() != "chatgpt.com" {
			t.Fatalf("hostname = %q, want chatgpt.com", req.URL.Hostname())
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("{}")),
			Request:    req,
		}, nil
	}))

	client := NewUtlsHTTPClient(ctx, nil, nil, 0)
	resp, err := client.Get("https://chatgpt.com/backend-api/codex/responses")
	if err != nil {
		t.Fatalf("client.Get returned error: %v", err)
	}
	if errClose := resp.Body.Close(); errClose != nil {
		t.Fatalf("response body close returned error: %v", errClose)
	}
	if !called {
		t.Fatal("expected context RoundTripper to handle protected host request")
	}
}

var (
	chatgptCertOnce sync.Once
	chatgptCert     stdtls.Certificate
)

// startChatgptServer serves TLS for chatgpt.com on loopback; utls trusts it through the test hook.
func startChatgptServer(t *testing.T, h2 bool, handler http.Handler) *httptest.Server {
	t.Helper()
	return startChatgptServerWithIdleTimeout(t, h2, handler, 0)
}

func startChatgptServerWithIdleTimeout(t *testing.T, h2 bool, handler http.Handler, idle time.Duration) *httptest.Server {
	t.Helper()
	chatgptCertOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "chatgpt.com"},
			DNSNames:     []string{"chatgpt.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			IsCA:         true,
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			panic(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			panic(err)
		}
		chatgptCert = stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
		roots := x509.NewCertPool()
		roots.AddCert(leaf)
		sharedUtlsMu.Lock()
		utlsTestRootCAs = roots
		sharedUtlsMu.Unlock()
	})
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = h2
	server.Config.IdleTimeout = idle
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{chatgptCert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func chatgptURL(server *httptest.Server, path string) string {
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	return "https://chatgpt.com:" + port + path
}

// connectProxy is an HTTP CONNECT proxy that sends every tunnel to loopback and counts them.
type connectProxy struct {
	url      string
	accepted atomic.Int32
	opened   atomic.Int32
	open     atomic.Int32

	mu      sync.Mutex
	tunnels []*proxyTunnel
}

type proxyTunnel struct {
	client   net.Conn
	dropping atomic.Bool
	stalled  atomic.Bool
}

// stallOpenTunnels stops reading from every open tunnel's client, so the client's writes back up
// until its TCP send buffer is full; resume reads again.
func (p *connectProxy) stallOpenTunnels() (resume func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	tunnels := slices.Clone(p.tunnels)
	for _, tun := range tunnels {
		tun.stalled.Store(true)
	}
	return func() {
		for _, tun := range tunnels {
			tun.stalled.Store(false)
		}
	}
}

// blackHoleOpenTunnels keeps every open tunnel's TCP connection up but drops its bytes.
func (p *connectProxy) blackHoleOpenTunnels() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tun := range p.tunnels {
		tun.dropping.Store(true)
	}
}

// closeOpenTunnels cuts every open tunnel without any HTTP/2 GOAWAY.
func (p *connectProxy) closeOpenTunnels() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, tun := range p.tunnels {
		_ = tun.client.Close()
	}
	p.tunnels = nil
}

func (tun *proxyTunnel) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		for src == tun.client && tun.stalled.Load() {
			time.Sleep(5 * time.Millisecond)
		}
		n, err := src.Read(buf)
		if n > 0 && !tun.dropping.Load() {
			if _, errWrite := dst.Write(buf[:n]); errWrite != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func startConnectProxy(t *testing.T, silent bool) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &connectProxy{url: "http://" + ln.Addr().String()}
	var conns sync.WaitGroup
	quit := make(chan struct{})
	t.Cleanup(func() {
		close(quit)
		_ = ln.Close()
		conns.Wait()
	})
	go func() {
		for {
			client, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			p.accepted.Add(1)
			conns.Add(1)
			go func() {
				<-quit
				_ = client.Close()
			}()
			go func() {
				defer conns.Done()
				defer client.Close()
				if !silent {
					p.tunnel(client)
				}
				<-quit
			}()
		}
	}()
	return p
}

func (p *connectProxy) tunnel(client net.Conn) {
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	_, port, _ := net.SplitHostPort(req.Host)
	upstream, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", port))
	if err != nil {
		return
	}
	defer upstream.Close()
	p.opened.Add(1)
	p.open.Add(1)
	defer p.open.Add(-1)
	if _, err = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	tun := &proxyTunnel{client: client}
	p.mu.Lock()
	p.tunnels = append(p.tunnels, tun)
	p.mu.Unlock()
	done := make(chan struct{}, 2)
	go func() { tun.pipe(upstream, client); done <- struct{}{} }()
	go func() { tun.pipe(client, upstream); done <- struct{}{} }()
	<-done
}

func newProxiedUtlsClient(proxyURL string) *http.Client {
	return NewUtlsHTTPClient(context.Background(), &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: proxyURL}}, nil, 0)
}

func getBody(ctx context.Context, proxyURL, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := newProxiedUtlsClient(proxyURL).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

// burst runs n concurrent GETs, each through a freshly built client, and returns the failures.
func burst(n int, proxyURL, url string) []error {
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, err := getBody(context.Background(), proxyURL, url)
			if err == nil && body != "HTTP/2.0" {
				err = fmt.Errorf("proto = %q, want HTTP/2.0", body)
			}
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	var out []error
	for err := range errs {
		out = append(out, err)
	}
	return out
}

func writeProto(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.Proto) }

func TestUtlsClientsShareOneTunnel(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)

	if errs := burst(50, p.url, chatgptURL(server, "/")); len(errs) > 0 {
		t.Fatalf("%d of 50 requests failed, first: %v", len(errs), errs[0])
	}
	if got := p.opened.Load(); got != 1 {
		t.Fatalf("tunnels opened = %d, want 1", got)
	}
}

func TestUtlsClientRedialsAfterServerClosesIdleConnection(t *testing.T) {
	t.Parallel()
	server := startChatgptServerWithIdleTimeout(t, true, http.HandlerFunc(writeProto), 200*time.Millisecond)
	p := startConnectProxy(t, false)
	url := chatgptURL(server, "/")

	if _, err := getBody(context.Background(), p.url, url); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for p.open.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("server never closed the idle connection")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if body, err := getBody(context.Background(), p.url, url); err != nil || body != "HTTP/2.0" {
		t.Fatalf("request after idle close: body=%q err=%v", body, err)
	}
	if got := p.opened.Load(); got != 2 {
		t.Fatalf("tunnels opened = %d, want 2", got)
	}
}

func TestUtlsClientRequestsReturnOnDeadlineWhenProxyIsSilent(t *testing.T) {
	t.Parallel()
	p := startConnectProxy(t, true)

	const n = 5
	var wg sync.WaitGroup
	results := make(chan error, n)
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			_, err := getBody(ctx, p.url, "https://chatgpt.com:1/")
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("requests took %v, want them back at their 300ms deadline", elapsed)
	}
	for err := range results {
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want context deadline exceeded", err)
		}
	}
	if got := p.accepted.Load(); got != 1 {
		t.Fatalf("proxy connections = %d, want 1 shared dial", got)
	}
}

func TestUtlsClientRetriesRequestsWhenServerSendsGoAway(t *testing.T) {
	t.Parallel()
	var served atomic.Int32
	server := startChatgptServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if served.Add(1)%25 == 0 {
			w.Header().Set("Connection", "close") // the HTTP/2 server answers with GOAWAY
		}
		writeProto(w, r)
	}))
	p := startConnectProxy(t, false)

	var wg sync.WaitGroup
	var failed atomic.Int32
	var firstErr atomic.Value
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 5; j++ {
				if _, err := getBody(context.Background(), p.url, chatgptURL(server, "/")); err != nil {
					failed.Add(1)
					firstErr.CompareAndSwap(nil, err)
				}
			}
		}()
	}
	wg.Wait()

	if n := failed.Load(); n > 0 {
		t.Fatalf("%d of 200 requests failed across GOAWAYs, first: %v", n, firstErr.Load())
	}
	if got := p.opened.Load(); got < 2 {
		t.Fatalf("tunnels opened = %d, want a reconnect after GOAWAY", got)
	}
}

func TestUtlsClientKeepsReceivingConnectionAfterCancelledRequest(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			<-r.Context().Done()
		case "/stream":
			for i := 0; i < 20; i++ {
				_, _ = io.WriteString(w, "x")
				w.(http.Flusher).Flush()
				time.Sleep(20 * time.Millisecond)
			}
		default:
			writeProto(w, r)
		}
	}))
	p := startConnectProxy(t, false)

	streamDone := make(chan error, 1)
	go func() {
		_, err := getBody(context.Background(), p.url, chatgptURL(server, "/stream"))
		streamDone <- err
	}()
	time.Sleep(60 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := getBody(ctx, p.url, chatgptURL(server, "/slow")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow request err = %v, want context deadline exceeded", err)
	}
	if err := <-streamDone; err != nil {
		t.Fatalf("stream on the shared connection failed: %v", err)
	}
	if _, err := getBody(context.Background(), p.url, chatgptURL(server, "/")); err != nil {
		t.Fatal(err)
	}
	if got := p.opened.Load(); got != 1 {
		t.Fatalf("tunnels opened = %d, want 1", got)
	}
}

func TestUtlsClientDropsSilentTunnelAndRedials(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)
	url := chatgptURL(server, "/")

	if _, err := getBody(context.Background(), p.url, url); err != nil {
		t.Fatal(err)
	}
	p.blackHoleOpenTunnels()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := getBody(ctx, p.url, url); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("request on the silent tunnel: err = %v, want context deadline exceeded", err)
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if body, err := getBody(ctx2, p.url, url); err != nil || body != "HTTP/2.0" {
		t.Fatalf("request after the silent tunnel: body=%q err=%v", body, err)
	}
	if got := p.opened.Load(); got != 2 {
		t.Fatalf("tunnels opened = %d, want a fresh tunnel after the silent one", got)
	}
}

func TestUtlsClientReplaysGetAfterAbruptClose(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)
	url := chatgptURL(server, "/")

	for i := 0; i < 100; i++ {
		if _, err := getBody(context.Background(), p.url, url); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		p.closeOpenTunnels()
	}
}

// h2Action is what rawH2Server does with the nth complete request it receives (n from 1).
type h2Action int

const (
	h2Respond h2Action = iota
	h2ProtocolError
	h2RefuseStream
	h2CloseConn
	h2GoAwayAbove    // GOAWAY whose last stream id is below this stream, then close
	h2GoAwayCovering // GOAWAY whose last stream id covers this stream, then close
	h2MissingStatus  // response HEADERS without :status
)

// rawH2Server is an HTTP/2 server for chatgpt.com that can answer a request it has fully read
// with a stream reset or a dropped connection, which net/http's server cannot be made to do.
type rawH2Server struct {
	port string
	hits atomic.Int32
}

func startRawH2Server(t *testing.T, action func(hit int32) h2Action) *rawH2Server {
	t.Helper()
	startChatgptServer(t, true, http.NotFoundHandler()) // installs the chatgpt.com cert and test roots
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{chatgptCert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &rawH2Server{}
	_, s.port, _ = net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			conn, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			go s.serve(conn, action)
		}
	}()
	return s
}

func (s *rawH2Server) url(proxyPath string) string {
	return "https://chatgpt.com:" + s.port + proxyPath
}

func (s *rawH2Server) serve(conn net.Conn, action func(hit int32) h2Action) {
	defer conn.Close()
	if _, err := io.ReadFull(conn, make([]byte, len(http2.ClientPreface))); err != nil {
		return
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		return
	}
	var headerBuf bytes.Buffer
	encoder := hpack.NewEncoder(&headerBuf)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			return
		}
		var streamID uint32
		switch f := frame.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				_ = framer.WriteSettingsAck()
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = framer.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			if f.StreamEnded() {
				streamID = f.StreamID
			}
		case *http2.DataFrame:
			if f.StreamEnded() {
				streamID = f.StreamID
			}
		}
		if streamID == 0 {
			continue
		}
		switch action(s.hits.Add(1)) {
		case h2ProtocolError:
			_ = framer.WriteRSTStream(streamID, http2.ErrCodeProtocol)
		case h2RefuseStream:
			_ = framer.WriteRSTStream(streamID, http2.ErrCodeRefusedStream)
		case h2CloseConn:
			return
		case h2GoAwayAbove:
			_ = framer.WriteGoAway(streamID-1, http2.ErrCodeNo, nil)
			return
		case h2GoAwayCovering:
			_ = framer.WriteGoAway(streamID, http2.ErrCodeNo, nil)
			return
		case h2MissingStatus:
			headerBuf.Reset()
			_ = encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
			_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: headerBuf.Bytes(), EndHeaders: true, EndStream: true})
		default:
			headerBuf.Reset()
			_ = encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			_ = framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: headerBuf.Bytes(), EndHeaders: true, EndStream: true})
		}
	}
}

func doRequest(proxyURL string, req *http.Request) error {
	resp, err := newProxiedUtlsClient(proxyURL).Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func TestUtlsClientSendsEachRequestAsOftenAsIsSafe(t *testing.T) {
	t.Parallel()
	firstThen := func(first h2Action) func(int32) h2Action {
		return func(hit int32) h2Action {
			if hit == 1 {
				return first
			}
			return h2Respond
		}
	}
	cases := []struct {
		name           string
		method         string
		idempotencyKey bool
		first          h2Action
		wantOK         bool
		wantHits       int32
	}{
		{"POST is not replayed after PROTOCOL_ERROR", http.MethodPost, false, h2ProtocolError, false, 1},
		{"POST is not replayed after an abrupt close", http.MethodPost, false, h2CloseConn, false, 1},
		{"POST is retried after REFUSED_STREAM", http.MethodPost, false, h2RefuseStream, true, 2},
		{"POST is retried after a GOAWAY below its stream", http.MethodPost, false, h2GoAwayAbove, true, 2},
		{"POST is not resent after a GOAWAY covering its stream", http.MethodPost, false, h2GoAwayCovering, false, 1},
		{"POST with an idempotency key is replayed once after an abrupt close", http.MethodPost, true, h2CloseConn, true, 2},
		{"GET is replayed once after an abrupt close", http.MethodGet, false, h2CloseConn, true, 2},
		{"GET is replayed once after PROTOCOL_ERROR", http.MethodGet, false, h2ProtocolError, true, 2},
		{"GET is not replayed after a malformed response", http.MethodGet, false, h2MissingStatus, false, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			server := startRawH2Server(t, firstThen(tc.first))
			p := startConnectProxy(t, false)
			var body io.Reader
			if tc.method == http.MethodPost {
				body = strings.NewReader(`{"charge":"once"}`)
			}
			req, err := http.NewRequest(tc.method, server.url("/"), body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.idempotencyKey {
				req.Header.Set("Idempotency-Key", "charge-once")
			}

			err = doRequest(p.url, req)

			if tc.wantOK && err != nil {
				t.Fatalf("request failed: %v", err)
			}
			if !tc.wantOK && err == nil {
				t.Fatal("request succeeded, want the first failure returned")
			}
			if got := server.hits.Load(); got != tc.wantHits {
				t.Fatalf("server received the request %d times, want %d", got, tc.wantHits)
			}
		})
	}
}

func TestUtlsClientReplaysOnlyOnceWhenTheFailureRepeats(t *testing.T) {
	t.Parallel()
	server := startRawH2Server(t, func(int32) h2Action { return h2CloseConn })
	p := startConnectProxy(t, false)
	req, err := http.NewRequest(http.MethodGet, server.url("/"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = doRequest(p.url, req); err == nil {
		t.Fatal("request succeeded against a server that always drops the connection")
	}
	if got := server.hits.Load(); got != 2 {
		t.Fatalf("server received the GET %d times, want 2", got)
	}
}

// countingBodies hands out request bodies and counts how often each is closed.
type countingBodies struct {
	mu     sync.Mutex
	closes []*atomic.Int32
}

type countedBody struct {
	io.Reader
	closes *atomic.Int32
}

func (b countedBody) Close() error { b.closes.Add(1); return nil }

func (c *countingBodies) next() io.ReadCloser {
	c.mu.Lock()
	defer c.mu.Unlock()
	closes := &atomic.Int32{}
	c.closes = append(c.closes, closes)
	return countedBody{Reader: strings.NewReader("payload"), closes: closes}
}

func TestUtlsClientClosesEveryAttemptsBodyExactlyOnce(t *testing.T) {
	t.Parallel()
	server := startRawH2Server(t, func(int32) h2Action { return h2RefuseStream })
	p := startConnectProxy(t, false)
	bodies := &countingBodies{}
	req, err := http.NewRequest(http.MethodPost, server.url("/"), bodies.next())
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len("payload"))
	req.GetBody = func() (io.ReadCloser, error) { return bodies.next(), nil }

	if err = doRequest(p.url, req); err == nil {
		t.Fatal("request succeeded against a server that refuses every stream")
	}
	bodies.mu.Lock()
	defer bodies.mu.Unlock()
	if len(bodies.closes) != maxUnprocessedRetries+1 {
		t.Fatalf("bodies used = %d, want %d attempts", len(bodies.closes), maxUnprocessedRetries+1)
	}
	for i, closes := range bodies.closes {
		if got := closes.Load(); got != 1 {
			t.Fatalf("body %d closed %d times, want once", i, got)
		}
	}
}

func TestUtlsClientCancelledRequestKeepsTheSharedConnection(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)
	url := chatgptURL(server, "/")

	if _, err := getBody(context.Background(), p.url, url); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := getBody(ctx, p.url, url); !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled request: err = %v, want context canceled", err)
		}
		if _, err := getBody(context.Background(), p.url, url); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.opened.Load(); got != 1 {
		t.Fatalf("tunnels opened = %d, want 1", got)
	}
}

func TestUtlsClientClosesBodyWhenNoConnectionIsObtained(t *testing.T) {
	t.Parallel()
	p := startConnectProxy(t, true)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	body := &closeTrackingBody{Reader: strings.NewReader("payload")}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://chatgpt.com:1/", body)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = newProxiedUtlsClient(p.url).Do(req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context deadline exceeded", err)
	}
	if !body.closed.Load() {
		t.Fatal("request body left open after waiting for the shared dial")
	}
}

func TestUtlsClientNamesSharedDialFailures(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	refused := "http://" + ln.Addr().String()
	_ = ln.Close()

	if _, err = getBody(context.Background(), refused, "https://chatgpt.com/"); err == nil || !strings.Contains(err.Error(), "utls: shared dial to chatgpt.com:443 failed") {
		t.Fatalf("err = %v, want a shared dial error", err)
	}
}

func TestEquivalentProxySettingsShareOneTransport(t *testing.T) {
	t.Parallel()
	same := func(a, b string) bool {
		return UtlsTransport(a) == UtlsTransport(b) && proxyTransport(a, "") == proxyTransport(b, "")
	}
	if !same("http://127.0.0.1:10", " HTTP://127.0.0.1:10/ ") {
		t.Fatal("equivalent proxy URLs got separate transports")
	}
	if UtlsTransport("") != UtlsTransport("DIRECT") || UtlsTransport("direct") != UtlsTransport("none") {
		t.Fatal("direct settings got separate utls transports")
	}
	if same("http://127.0.0.1:10", "http://127.0.0.1:11") {
		t.Fatal("different proxies share a transport")
	}
}

func TestUtlsClientKeepsOneConnectionPerAccount(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: p.url}}

	for _, id := range []string{"account-a", "account-b", "account-a", "account-b", "account-a"} {
		resp, err := NewUtlsHTTPClient(context.Background(), cfg, &cliproxyauth.Auth{ID: id}, 0).Get(chatgptURL(server, "/"))
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	if got := p.opened.Load(); got != 2 {
		t.Fatalf("tunnels opened = %d, want one per account", got)
	}
	if NewProxyAwareHTTPClient(context.Background(), cfg, &cliproxyauth.Auth{ID: "account-a"}, 0).Transport ==
		NewProxyAwareHTTPClient(context.Background(), cfg, &cliproxyauth.Auth{ID: "account-b"}, 0).Transport {
		t.Fatal("two accounts share the fallback transport")
	}
}

func TestUtlsClientRejectsServerThatDoesNotNegotiateHTTP2(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, false, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)

	_, err := getBody(context.Background(), p.url, chatgptURL(server, "/"))
	if err == nil || !strings.Contains(err.Error(), `want "h2"`) {
		t.Fatalf("err = %v, want an ALPN h2 error", err)
	}
}

func TestInvalidProxyURLFailsEveryRequestAndIsNotCached(t *testing.T) {
	t.Parallel()
	const badProxy = "ftp://proxy.invalid:21"
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: badProxy}}

	for name, client := range map[string]*http.Client{
		"utls":        NewUtlsHTTPClient(context.Background(), cfg, nil, 0),
		"proxy-aware": NewProxyAwareHTTPClient(context.Background(), cfg, nil, 0),
	} {
		for _, url := range []string{"https://chatgpt.com/", "https://example.com/"} {
			if _, err := client.Get(url); err == nil || !strings.Contains(err.Error(), "invalid proxy") {
				t.Fatalf("%s %s: err = %v, want invalid proxy error", name, url, err)
			}
		}
	}
	sharedUtlsMu.Lock()
	for key := range sharedUtlsTransports {
		if strings.Contains(key.proxy, "proxy.invalid") {
			t.Errorf("invalid proxy cached in utls transports: %s", key.proxy)
		}
	}
	sharedUtlsMu.Unlock()
	sharedProxyMu.Lock()
	for key := range sharedProxyTransports {
		if strings.Contains(key.proxy, "proxy.invalid") {
			t.Errorf("invalid proxy cached in proxy transports: %s", key.proxy)
		}
	}
	sharedProxyMu.Unlock()
}

func TestClientsForTheSameProxyShareTheFallbackTransport(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "http://127.0.0.1:9"}}

	first := NewProxyAwareHTTPClient(context.Background(), cfg, nil, 0).Transport
	if second := NewProxyAwareHTTPClient(context.Background(), cfg, nil, 0).Transport; first != second {
		t.Fatal("proxy-aware clients built separate transports for one proxy")
	}
	if fallback := NewUtlsHTTPClient(context.Background(), cfg, nil, 0).Transport.(*fallbackRoundTripper).fallback; fallback != first {
		t.Fatal("utls client fallback does not share the proxy transport")
	}
}

type closeTrackingBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *closeTrackingBody) Close() error { b.closed.Store(true); return nil }

func TestInvalidProxyURLClosesTheRequestBody(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: "ftp://proxy.invalid:21"}}

	for name, client := range map[string]*http.Client{
		"utls":        NewUtlsHTTPClient(context.Background(), cfg, nil, 0),
		"proxy-aware": NewProxyAwareHTTPClient(context.Background(), cfg, nil, 0),
	} {
		for _, url := range []string{"https://chatgpt.com/", "https://example.com/"} {
			body := &closeTrackingBody{Reader: strings.NewReader("payload")}
			req, err := http.NewRequest(http.MethodPost, url, body)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = client.Do(req); err == nil {
				t.Fatalf("%s %s: expected invalid proxy error", name, url)
			}
			if !body.closed.Load() {
				t.Fatalf("%s %s: request body left open", name, url)
			}
		}
	}
}

// startFlakyFirstConnServer serves healthy HTTP/2 except on its first connection, which it
// closes right after the TLS handshake, before any stream.
func startFlakyFirstConnServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	startChatgptServer(t, true, http.NotFoundHandler())
	ln, err := stdtls.Listen("tcp", "127.0.0.1:0", &stdtls.Config{Certificates: []stdtls.Certificate{chatgptCert}, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted atomic.Int32
	h2s := &http2.Server{}
	go func() {
		for {
			conn, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			first := accepted.Add(1) == 1
			go func() {
				if errHandshake := conn.(*stdtls.Conn).Handshake(); errHandshake != nil || first {
					_ = conn.Close()
					return
				}
				h2s.ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(writeProto)})
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "https://chatgpt.com:" + port + "/", &accepted
}

func TestReviewNotEstablishedConnIsReused(t *testing.T) {
	t.Parallel()
	url, accepted := startFlakyFirstConnServer(t)
	proxy := startConnectProxy(t, false)

	// A caller that gives up at once leaves the shared dial to finish on its own, so the pool
	// holds a conn the server closes before its first stream.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	_, _ = getBody(ctx, proxy.url, url)
	cancel()
	time.Sleep(300 * time.Millisecond)

	fails := 0
	for i := 0; i < 20; i++ {
		if _, err := getBody(context.Background(), proxy.url, url); err == nil {
			if fails > 1 {
				t.Fatalf("%d requests failed on the dead conn before one redialled", fails)
			}
			if accepted.Load() < 2 {
				t.Fatal("request succeeded without a new connection")
			}
			return
		}
		fails++
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("all %d requests failed on a conn that died before its first stream; none redialled", fails)
}

func TestUtlsClientWaitsBeforeRetryingAndStopsWhenCancelled(t *testing.T) {
	old := retryBackoff
	retryBackoff = func(int) time.Duration { return time.Hour }
	defer func() { retryBackoff = old }()
	server := startRawH2Server(t, func(int32) h2Action { return h2RefuseStream })
	proxy := startConnectProxy(t, false)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	body := &closeTrackingBody{Reader: strings.NewReader("payload")}
	rewound := &closeTrackingBody{Reader: strings.NewReader("payload")}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.url("/"), body)
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = func() (io.ReadCloser, error) { return rewound, nil }

	start := time.Now()
	err = doRequest(proxy.url, req)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the request's deadline", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("returned after %v; the cancelled wait did not stop", elapsed)
	}
	if hits := server.hits.Load(); hits != 1 {
		t.Fatalf("server hits = %d, want 1: the retry did not wait", hits)
	}
	if !body.closed.Load() || !rewound.closed.Load() {
		t.Fatalf("bodies left open: original closed=%v, rewound closed=%v", body.closed.Load(), rewound.closed.Load())
	}
}

func TestUtlsClientReturnsTheRewindErrorWithoutWaiting(t *testing.T) {
	old := retryBackoff
	retryBackoff = func(int) time.Duration { return time.Hour }
	defer func() { retryBackoff = old }()
	server := startRawH2Server(t, func(int32) h2Action { return h2RefuseStream })
	proxy := startConnectProxy(t, false)

	errRewind := errors.New("payload gone")
	req, err := http.NewRequest(http.MethodPost, server.url("/"), io.NopCloser(strings.NewReader("payload")))
	if err != nil {
		t.Fatal(err)
	}
	req.GetBody = func() (io.ReadCloser, error) { return nil, errRewind }

	done := make(chan error, 1)
	go func() { done <- doRequest(proxy.url, req) }()
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("waited for the retry before finding the body could not be rewound")
	}
	if !errors.Is(err, errRewind) {
		t.Fatalf("err = %v, want the rewind error", err)
	}
}

// pooledConns returns the account-less shared connections for proxyURL.
func pooledConns(t *testing.T, proxyURL string) []*utlsPooledConn {
	t.Helper()
	rt, err := sharedUtlsTransport(proxyURL, "")
	if err != nil {
		t.Fatal(err)
	}
	rt.pool.mu.Lock()
	defer rt.pool.mu.Unlock()
	var out []*utlsPooledConn
	for _, list := range rt.pool.conns {
		out = append(out, list...)
	}
	return out
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUtlsClientRetiresSilentTunnelWhenAStreamedResponseIsCancelled(t *testing.T) {
	t.Parallel()
	quit := make(chan struct{})
	server := startChatgptServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sse" {
			writeProto(w, r)
			return
		}
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-quit:
		}
	}))
	t.Cleanup(func() { close(quit) })
	p := startConnectProxy(t, false)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, chatgptURL(server, "/sse"), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := newProxiedUtlsClient(p.url).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = resp.Body.Read(make([]byte, 64)); err != nil {
		t.Fatalf("first event: %v", err)
	}
	p.blackHoleOpenTunnels()
	cancel()
	if _, err = io.ReadAll(resp.Body); !errors.Is(err, context.Canceled) {
		t.Fatalf("read after cancel: err = %v, want context canceled", err)
	}
	_ = resp.Body.Close()

	next, cancelNext := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelNext()
	if body, err := getBody(next, p.url, chatgptURL(server, "/")); err != nil || body != "HTTP/2.0" {
		t.Fatalf("request after the silent stream: body=%q err=%v", body, err)
	}
	if got := p.opened.Load(); got != 2 {
		t.Fatalf("tunnels opened = %d, want a fresh tunnel after the silent one", got)
	}
	waitFor(t, "the silent tunnel to close", func() bool { return p.open.Load() == 1 })
}

func TestUtlsClientClosesARetiredConnectionStuckBehindAFullSendBuffer(t *testing.T) {
	t.Parallel()
	startChatgptServer(t, true, http.NotFoundHandler()) // installs the chatgpt.com cert and test roots
	// Large flow-control windows let the client write until its TCP send buffer is full.
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		writeProto(w, r)
	}))
	server.EnableHTTP2 = true
	server.Config.HTTP2 = &http.HTTP2Config{MaxReceiveBufferPerConnection: 64 << 20, MaxReceiveBufferPerStream: 64 << 20}
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{chatgptCert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	p := startConnectProxy(t, false)
	url := chatgptURL(server, "/")

	if _, err := getBody(context.Background(), p.url, url); err != nil {
		t.Fatal(err)
	}
	conns := pooledConns(t, p.url)
	if len(conns) != 1 {
		t.Fatalf("pooled conns = %d, want 1", len(conns))
	}
	resume := p.stallOpenTunnels()
	defer resume()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(make([]byte, 48<<20)))
	if err != nil {
		t.Fatal(err)
	}
	if err = doRequest(p.url, req); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("POST on the stalled tunnel: err = %v, want context deadline exceeded", err)
	}
	waitFor(t, "the retired connection's socket to close", conns[0].dead.Load)
	if body, err := getBody(context.Background(), p.url, url); err != nil || body != "HTTP/2.0" {
		t.Fatalf("request after the stalled tunnel: body=%q err=%v", body, err)
	}
}

func TestUtlsClientDropsClosedConnectionsFromThePool(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(writeProto))
	p := startConnectProxy(t, false)
	url := chatgptURL(server, "/")

	if _, err := getBody(context.Background(), p.url, url); err != nil {
		t.Fatal(err)
	}
	first := pooledConns(t, p.url)
	if len(first) != 1 {
		t.Fatalf("pooled conns = %d, want 1", len(first))
	}
	p.closeOpenTunnels()
	waitFor(t, "the cut connection to be seen as closed", first[0].dead.Load)
	if _, err := getBody(context.Background(), p.url, url); err != nil {
		t.Fatal(err)
	}
	if got := pooledConns(t, p.url); len(got) != 1 || got[0] == first[0] {
		t.Fatalf("pool after the cut = %d conns (closed one kept: %v), want only the new one", len(got), slices.Contains(got, first[0]))
	}
}

func TestUtlsClientReplaysOnlySafeRequestsAfterAForcedClose(t *testing.T) {
	t.Parallel()
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			var hits atomic.Int32
			arrived := make(chan struct{}, 1)
			quit := make(chan struct{})
			server := startChatgptServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if hits.Add(1) == 1 {
					arrived <- struct{}{}
					select {
					case <-r.Context().Done():
					case <-quit:
					}
					return
				}
				writeProto(w, r)
			}))
			t.Cleanup(func() { close(quit) })
			p := startConnectProxy(t, false)

			req, err := http.NewRequest(method, chatgptURL(server, "/"), strings.NewReader("payload"))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- doRequest(p.url, req) }()
			<-arrived
			conns := pooledConns(t, p.url)
			if len(conns) != 1 {
				t.Fatalf("pooled conns = %d, want 1", len(conns))
			}
			_ = conns[0].cc.Close()
			err = <-done
			if method == http.MethodGet {
				if err != nil || hits.Load() != 2 {
					t.Fatalf("GET: err=%v hits=%d, want replayed once and succeeded", err, hits.Load())
				}
				return
			}
			if err == nil || hits.Load() != 1 {
				t.Fatalf("POST: err=%v hits=%d, want the forced close returned and no resend", err, hits.Load())
			}
		})
	}
}
