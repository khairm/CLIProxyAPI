package helps

import (
	"bufio"
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
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

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
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, client); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
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

func TestUtlsClientKeepsSharedConnectionAfterCancelledRequest(t *testing.T) {
	t.Parallel()
	server := startChatgptServer(t, true, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
			return
		}
		writeProto(w, r)
	}))
	p := startConnectProxy(t, false)

	if _, err := getBody(context.Background(), p.url, chatgptURL(server, "/")); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := getBody(ctx, p.url, chatgptURL(server, "/slow")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("slow request err = %v, want context deadline exceeded", err)
	}
	if _, err := getBody(context.Background(), p.url, chatgptURL(server, "/")); err != nil {
		t.Fatal(err)
	}
	if got := p.opened.Load(); got != 1 {
		t.Fatalf("tunnels opened = %d, want 1", got)
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
	_, cachedUtls := sharedUtlsTransports[badProxy]
	sharedUtlsMu.Unlock()
	sharedProxyMu.Lock()
	_, cachedProxy := sharedProxyTransports[badProxy]
	sharedProxyMu.Unlock()
	if cachedUtls || cachedProxy {
		t.Fatalf("invalid proxy cached: utls=%v proxy=%v", cachedUtls, cachedProxy)
	}
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
