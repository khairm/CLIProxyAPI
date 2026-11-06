package executor

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const (
	codexPoolCreatedEvent   = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"r1\"}}\n\n"
	codexPoolCompletedEvent = "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n"
)

// startCodexChatgptServer serves handler over HTTP/2 with a chatgpt.com certificate the uTLS
// pool trusts, so CodexExecutor traffic goes through the shared pool.
func startCodexChatgptServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
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
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	helps.SetUtlsRootCAsForTest(roots)
	t.Cleanup(func() { helps.SetUtlsRootCAsForTest(nil) })
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = true
	server.TLS = &stdtls.Config{Certificates: []stdtls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// codexTunnelProxy is a CONNECT proxy that sends every tunnel to the local server and counts them.
// With drop set it stops forwarding bytes while keeping tunnels open.
type codexTunnelProxy struct {
	url    string
	opened atomic.Int32
	open   atomic.Int32
	drop   atomic.Bool
}

func startCodexTunnelProxy(t *testing.T) *codexTunnelProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &codexTunnelProxy{url: "http://" + ln.Addr().String()}
	go func() {
		for {
			client, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			go p.serve(client)
		}
	}()
	return p
}

func (p *codexTunnelProxy) serve(client net.Conn) {
	defer client.Close()
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
	_, _ = io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n")
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := make([]byte, 32*1024)
		for {
			n, errRead := src.Read(buf)
			if n > 0 && !p.drop.Load() {
				if _, errWrite := dst.Write(buf[:n]); errWrite != nil {
					break
				}
			}
			if errRead != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
}

func codexPoolExecutor(p *codexTunnelProxy, server *httptest.Server, authID string) (*CodexExecutor, *cliproxyauth.Auth) {
	_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
	auth := &cliproxyauth.Auth{ID: authID, Attributes: map[string]string{
		"base_url": "https://chatgpt.com:" + port + "/backend-api/codex",
		"api_key":  "test",
	}}
	return NewCodexExecutor(&config.Config{SDKConfig: sdkconfig.SDKConfig{ProxyURL: p.url}}), auth
}

func codexPoolStream(t *testing.T, ctx context.Context, exec *CodexExecutor, auth *cliproxyauth.Auth) *cliproxyexecutor.StreamResult {
	t.Helper()
	result, err := exec.ExecuteStream(ctx, auth,
		cliproxyexecutor.Request{Model: "gpt-5.5", Payload: []byte(`{"model":"gpt-5.5","input":"hello"}`)},
		cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response"), Stream: true})
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	return result
}

func TestUtlsClientCodexStreamCancelledAfterCompletedKeepsTheTunnel(t *testing.T) {
	server := startCodexChatgptServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, codexPoolCreatedEvent+codexPoolCompletedEvent)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	p := startCodexTunnelProxy(t)
	exec, auth := codexPoolExecutor(p, server, "codex-pool-completed")
	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		result := codexPoolStream(t, ctx, exec, auth)
		saw := false
		for chunk := range result.Chunks {
			if chunk.Err != nil {
				t.Fatalf("request %d: %v", i, chunk.Err)
			}
			if strings.Contains(string(chunk.Payload), "response.completed") {
				saw = true
				cancel()
				break
			}
		}
		for range result.Chunks {
		}
		cancel()
		if !saw {
			t.Fatalf("request %d never saw response.completed", i)
		}
	}
	if got := p.opened.Load(); got != 1 {
		t.Fatalf("tunnels opened = %d, want 1", got)
	}
}

func TestUtlsClientCodexStreamSilentWithoutFinalEventRetiresTheTunnel(t *testing.T) {
	quit := make(chan struct{})
	t.Cleanup(func() { close(quit) })
	server := startCodexChatgptServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, codexPoolCreatedEvent)
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-quit:
		}
	}))
	p := startCodexTunnelProxy(t)
	exec, auth := codexPoolExecutor(p, server, "codex-pool-silent")

	ctx, cancel := context.WithCancel(context.Background())
	result := codexPoolStream(t, ctx, exec, auth)
	<-result.Chunks
	p.drop.Store(true)
	cancel()
	for range result.Chunks {
	}
	deadline := time.Now().Add(3 * time.Second)
	for p.open.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := p.open.Load(); got != 0 {
		t.Fatalf("silent tunnel still open: %d", got)
	}

	p.drop.Store(false)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	result = codexPoolStream(t, ctx2, exec, auth)
	if chunk := <-result.Chunks; chunk.Err != nil {
		t.Fatalf("request after the silent stream: %v", chunk.Err)
	}
	cancel2()
	for range result.Chunks {
	}
	if got := p.opened.Load(); got != 2 {
		t.Fatalf("tunnels opened = %d, want 2", got)
	}
}
