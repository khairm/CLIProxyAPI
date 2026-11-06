package helps

import (
	"bufio"
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// countingConnectProxy is an HTTP CONNECT proxy that counts open tunnels.
type countingConnectProxy struct {
	ln     net.Listener
	opened atomic.Int32
	open   atomic.Int32
}

func startCountingConnectProxy(t *testing.T) *countingConnectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &countingConnectProxy{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
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

func (p *countingConnectProxy) serve(client net.Conn) {
	defer client.Close()
	req, err := http.ReadRequest(bufio.NewReader(client))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	upstream, err := net.Dial("tcp", req.Host)
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

func TestUtlsRoundTripperSharesOneTunnelPerProxyAndClosesItWhenIdle(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	proxyServer := startCountingConnectProxy(t)
	proxyURL := "http://" + proxyServer.ln.Addr().String()

	rt := sharedUtlsRoundTripper(proxyURL)
	rt.rootCAs = x509.NewCertPool()
	rt.rootCAs.AddCert(server.Certificate())
	rt.h2.IdleConnTimeout = 300 * time.Millisecond

	for i := 0; i < 5; i++ {
		req, err := http.NewRequest(http.MethodGet, server.URL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := sharedUtlsRoundTripper(proxyURL).RoundTrip(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "HTTP/2.0" {
			t.Fatalf("request %d proto = %q, want HTTP/2.0", i, body)
		}
	}

	if got := proxyServer.opened.Load(); got != 1 {
		t.Fatalf("tunnels opened = %d, want 1", got)
	}
	deadline := time.Now().Add(5 * time.Second)
	for proxyServer.open.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("idle tunnel still open after idle timeout")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
