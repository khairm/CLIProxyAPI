package proxyutil

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

// startFakeConnectProxy runs respond on every connection after reading its CONNECT request.
func startFakeConnectProxy(t *testing.T, respond func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, errAccept := ln.Accept()
			if errAccept != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, errRead := http.ReadRequest(bufio.NewReader(conn)); errRead != nil {
					return
				}
				respond(conn)
			}()
		}
	}()
	return "http://" + ln.Addr().String()
}

func connectDialer(t *testing.T, proxyURL string) proxy.ContextDialer {
	t.Helper()
	dialer, _, err := BuildDialer(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return dialer.(proxy.ContextDialer)
}

func TestConnectDialReturnsWhenContextEndsAndClosesProxyConn(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		ctx  func() (context.Context, context.CancelFunc)
		want error
	}{
		"deadline": {func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 200*time.Millisecond)
		}, context.DeadlineExceeded},
		"cancel": {func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(100*time.Millisecond, cancel)
			return ctx, cancel
		}, context.Canceled},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			closed := make(chan struct{})
			proxyURL := startFakeConnectProxy(t, func(conn net.Conn) {
				_, _ = conn.Read(make([]byte, 1)) // stays silent until the client hangs up
				close(closed)
			})
			ctx, cancel := tc.ctx()
			defer cancel()
			start := time.Now()
			_, err := connectDialer(t, proxyURL).DialContext(ctx, "tcp", "example.com:443")
			if !errors.Is(err, tc.want) || time.Since(start) > 2*time.Second {
				t.Fatalf("err = %v after %v, want %v promptly", err, time.Since(start), tc.want)
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("proxy connection left open after failed dial")
			}
		})
	}
}

func TestConnectTunnelOutlivesDialContext(t *testing.T) {
	t.Parallel()
	proxyURL := startFakeConnectProxy(t, func(conn net.Conn) {
		_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		time.Sleep(400 * time.Millisecond)
		_, _ = io.WriteString(conn, "late")
		_, _ = conn.Read(make([]byte, 1))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	conn, err := connectDialer(t, proxyURL).DialContext(ctx, "tcp", "example.com:443")
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4)
	if _, errRead := io.ReadFull(conn, buf); errRead != nil || string(buf) != "late" {
		t.Fatalf("tunnel read after dial context ended: err = %v, got %q", errRead, buf)
	}
}

// RFC 9110 9.3.6: framing headers on a 2xx CONNECT reply must be ignored; the bytes after it are tunnel data.
func TestConnectSuccessIgnoresFramingHeadersAndKeepsTunnelBytes(t *testing.T) {
	t.Parallel()
	for name, header := range map[string]string{
		"content-length": "Content-Length: 3\r\n",
		"chunked":        "Transfer-Encoding: chunked\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			proxyURL := startFakeConnectProxy(t, func(conn net.Conn) {
				_, _ = io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n"+header+"\r\nTLS!")
				_, _ = conn.Read(make([]byte, 1))
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			start := time.Now()
			conn, err := connectDialer(t, proxyURL).DialContext(ctx, "tcp", "example.com:443")
			if err != nil || time.Since(start) > time.Second {
				t.Fatalf("dial: err = %v after %v", err, time.Since(start))
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 4)
			if _, errRead := io.ReadFull(conn, buf); errRead != nil || string(buf) != "TLS!" {
				t.Fatalf("tunnel bytes: err = %v, got %q, want %q", errRead, buf, "TLS!")
			}
		})
	}
}

func TestConnectRejectedReturnsStatusError(t *testing.T) {
	t.Parallel()
	closed := make(chan struct{})
	proxyURL := startFakeConnectProxy(t, func(conn net.Conn) {
		_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nTransfer-Encoding: chunked\r\n\r\n")
		_, _ = conn.Read(make([]byte, 1))
		close(closed)
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := connectDialer(t, proxyURL).DialContext(ctx, "tcp", "example.com:443")
	if err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want a 407 status error", err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("proxy connection left open after rejected CONNECT")
	}
}
