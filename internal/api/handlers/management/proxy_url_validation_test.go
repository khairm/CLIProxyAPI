package management

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

const goodProxy = "http://proxy.local:8080"

func proxyTestConfig() *config.Config {
	return &config.Config{
		GeminiKey:          []config.GeminiKey{{APIKey: "k", ProxyURL: goodProxy}},
		InteractionsKey:    []config.GeminiKey{{APIKey: "k", ProxyURL: goodProxy}},
		ClaudeKey:          []config.ClaudeKey{{APIKey: "k", ProxyURL: goodProxy}},
		CodexKey:           []config.CodexKey{{APIKey: "k", BaseURL: "https://codex.example.com", ProxyURL: goodProxy}},
		VertexCompatAPIKey: []config.VertexCompatKey{{APIKey: "k", BaseURL: "https://vertex.example.com", ProxyURL: goodProxy}},
		OpenAICompatibility: []config.OpenAICompatibility{{
			Name:          "compat",
			BaseURL:       "https://compat.example.com",
			APIKeyEntries: []config.OpenAICompatibilityAPIKey{{APIKey: "k", ProxyURL: goodProxy}},
		}},
	}
}

func serveJSON(handler gin.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(method, "/", strings.NewReader(body))
	ctx.Request.Header.Set("Content-Type", "application/json")
	handler(ctx)
	return rec
}

// Every config handler that takes a proxy URL answers 400 for a bad one and changes neither the config nor its file.
func TestConfigHandlersRejectInvalidProxyURLWithoutChanges(t *testing.T) {
	gin.SetMode(gin.TestMode)
	bad := []string{"ftp://p:21", "http://:8080", "http://p:99999", "socks5://p"}
	type handlerCase struct {
		name   string
		method string
		call   func(*Handler) gin.HandlerFunc
		body   string // %s is the bad proxy URL
	}
	cases := []handlerCase{
		{"PutProxyURL", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutProxyURL }, `{"value":"%s"}`},
		{"PutGeminiKeys", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutGeminiKeys }, `[{"api-key":"k","proxy-url":"%s"}]`},
		{"PutInteractionsKeys", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutInteractionsKeys }, `[{"api-key":"k","proxy-url":"%s"}]`},
		{"PutClaudeKeys", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutClaudeKeys }, `[{"api-key":"k","proxy-url":"%s"}]`},
		{"PutCodexKeys", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutCodexKeys }, `[{"api-key":"k","base-url":"https://c.example.com","proxy-url":"%s"}]`},
		{"PutVertexCompatKeys", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutVertexCompatKeys }, `[{"api-key":"k","base-url":"https://v.example.com","proxy-url":"%s"}]`},
		{"PutOpenAICompat", http.MethodPut, func(h *Handler) gin.HandlerFunc { return h.PutOpenAICompat }, `[{"name":"compat","base-url":"https://c.example.com","api-key-entries":[{"api-key":"k","proxy-url":"%s"}]}]`},
		{"PatchGeminiKey", http.MethodPatch, func(h *Handler) gin.HandlerFunc { return h.PatchGeminiKey }, `{"index":0,"value":{"prefix":"changed","proxy-url":"%s"}}`},
		{"PatchInteractionsKey", http.MethodPatch, func(h *Handler) gin.HandlerFunc { return h.PatchInteractionsKey }, `{"index":0,"value":{"prefix":"changed","proxy-url":"%s"}}`},
		{"PatchClaudeKey", http.MethodPatch, func(h *Handler) gin.HandlerFunc { return h.PatchClaudeKey }, `{"index":0,"value":{"prefix":"changed","proxy-url":"%s"}}`},
		{"PatchCodexKey", http.MethodPatch, func(h *Handler) gin.HandlerFunc { return h.PatchCodexKey }, `{"index":0,"value":{"prefix":"changed","proxy-url":"%s"}}`},
		{"PatchVertexCompatKey", http.MethodPatch, func(h *Handler) gin.HandlerFunc { return h.PatchVertexCompatKey }, `{"index":0,"value":{"prefix":"changed","proxy-url":"%s"}}`},
		{"PatchOpenAICompat", http.MethodPatch, func(h *Handler) gin.HandlerFunc { return h.PatchOpenAICompat }, `{"index":0,"value":{"prefix":"changed","api-key-entries":[{"api-key":"k","proxy-url":"%s"}]}}`},
	}
	for _, tc := range cases {
		for _, proxyURL := range bad {
			t.Run(tc.name+" "+proxyURL, func(t *testing.T) {
				path := writeTestConfigFile(t)
				h := &Handler{cfg: proxyTestConfig(), configFilePath: path}
				fileBefore, _ := os.ReadFile(path)

				rec := serveJSON(tc.call(h), tc.method, strings.Replace(tc.body, "%s", proxyURL, 1))

				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
				}
				if !reflect.DeepEqual(h.cfg, proxyTestConfig()) {
					t.Fatal("config changed by a rejected request")
				}
				if fileAfter, _ := os.ReadFile(path); !bytes.Equal(fileBefore, fileAfter) {
					t.Fatal("config file changed by a rejected request")
				}
			})
		}
	}
}

func TestPatchAuthFileFieldsRejectsBadProxyURLWithoutChanges(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	bodies := map[string]string{
		"bad scheme":   `{"name":"a.json","prefix":"changed","nested.value":"changed","proxy_url":"ftp://p:21"}`,
		"no hostname":  `{"name":"a.json","nested.value":"changed","proxy_url":"http://:8080"}`,
		"number":       `{"name":"a.json","nested.value":"changed","proxy_url":123}`,
		"bool":         `{"name":"a.json","nested.value":"changed","proxy_url":false}`,
		"object":       `{"name":"a.json","nested.value":"changed","proxy_url":{"host":"p"}}`,
		"nested write": `{"name":"a.json","nested.value":"changed","proxy_url.host":"broken"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
			record := &coreauth.Auth{
				ID:       "a.json",
				FileName: "a.json",
				Provider: "codex",
				Metadata: map[string]any{"type": "codex", "proxy_url": goodProxy, "nested": map[string]any{"value": "old"}},
			}
			if _, err := manager.Register(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)

			rec := serveJSON(h.PatchAuthFileFields, http.MethodPatch, body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			live, _ := manager.GetByID("a.json")
			if got := live.Metadata["proxy_url"]; got != goodProxy {
				t.Fatalf("proxy_url = %#v, want unchanged", got)
			}
			if got := live.Metadata["nested"].(map[string]any)["value"]; got != "old" {
				t.Fatalf("nested.value = %#v, want unchanged", got)
			}
			if _, ok := live.Metadata["prefix"]; ok {
				t.Fatal("prefix applied by a rejected patch")
			}
		})
	}
}

func TestUploadAuthFileRejectsBadProxyURL(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	for _, proxyField := range []string{`"ftp://p:21"`, `123`, `"socks5://p"`} {
		t.Run(proxyField, func(t *testing.T) {
			authDir := t.TempDir()
			manager := coreauth.NewManager(nil, nil, nil)
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

			var body bytes.Buffer
			writer := multipart.NewWriter(&body)
			part, err := writer.CreateFormFile("file", "codex-a.json")
			if err != nil {
				t.Fatal(err)
			}
			_, _ = part.Write([]byte(`{"type":"codex","proxy_url":` + proxyField + `}`))
			_ = writer.Close()
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/", &body)
			ctx.Request.Header.Set("Content-Type", writer.FormDataContentType())

			h.UploadAuthFile(ctx)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
			}
			if _, errStat := os.Stat(filepath.Join(authDir, "codex-a.json")); !os.IsNotExist(errStat) {
				t.Fatalf("auth file written despite the bad proxy: %v", errStat)
			}
			if _, ok := manager.GetByID("codex-a.json"); ok {
				t.Fatal("auth registered despite the bad proxy")
			}
		})
	}
}

func registerPatchTarget(t *testing.T) (*coreauth.Manager, *Handler) {
	t.Helper()
	manager := coreauth.NewManager(&memoryAuthStore{}, nil, nil)
	record := &coreauth.Auth{
		ID:       "a.json",
		FileName: "a.json",
		Provider: "codex",
		ProxyURL: goodProxy,
		Metadata: map[string]any{"type": "codex", "proxy_url": goodProxy, "nested": map[string]any{"value": "old"}},
	}
	if _, err := manager.Register(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	return manager, NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, manager)
}

// A patch that fails partway through applying leaves the live record untouched, whatever order its fields apply in.
func TestPatchAuthFileFieldsFailingMidApplyLeavesLiveRecordUnchanged(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	for i := 0; i < 20; i++ {
		manager, h := registerPatchTarget(t)

		rec := serveJSON(h.PatchAuthFileFields, http.MethodPatch, `{"name":"a.json","nested.value":"changed","bad..path":"x"}`)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
		}
		live, _ := manager.GetByID("a.json")
		if got := live.Metadata["nested"].(map[string]any)["value"]; got != "old" {
			t.Fatalf("run %d: nested.value = %#v, want unchanged", i, got)
		}
	}
}

func TestPatchAuthFileFieldsNullProxyURLClearsTheLiveProxy(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	gin.SetMode(gin.TestMode)
	manager, h := registerPatchTarget(t)

	rec := serveJSON(h.PatchAuthFileFields, http.MethodPatch, `{"name":"a.json","proxy_url":null}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	live, _ := manager.GetByID("a.json")
	if live.ProxyURL != "" {
		t.Fatalf("live ProxyURL = %q, want it cleared like the saved proxy_url", live.ProxyURL)
	}
	if got, _ := live.Metadata["proxy_url"].(string); got != "" {
		t.Fatalf("saved proxy_url = %#v, want cleared", live.Metadata["proxy_url"])
	}
}
