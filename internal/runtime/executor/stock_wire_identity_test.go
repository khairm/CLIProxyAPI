package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type stockWireFixture struct {
	Name    string              `json:"name"`
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	Outcome string              `json:"outcome"`
}

type stockWireFixtureSet struct {
	StockTag    string             `json:"stock_tag"`
	StockCommit string             `json:"stock_commit"`
	Fixtures    []stockWireFixture `json:"fixtures"`
}

const patchedStockWireFixtureCommit = "3554b63721aac9b4202bf2ef88ba7a82b4e5caf8"

func loadStockWireFixtures(t *testing.T) stockWireFixtureSet {
	t.Helper()
	path := filepath.Join("testdata", "stock_v7.2.62_wire.json")
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read %s: %v", path, errRead)
	}
	var fixtures stockWireFixtureSet
	if errUnmarshal := json.Unmarshal(data, &fixtures); errUnmarshal != nil {
		t.Fatalf("decode %s: %v", path, errUnmarshal)
	}
	if fixtures.StockTag != "v7.2.62" || fixtures.StockCommit != patchedStockWireFixtureCommit {
		t.Fatalf("fixture provenance = %q at %q, want v7.2.62 at %s", fixtures.StockTag, fixtures.StockCommit, patchedStockWireFixtureCommit)
	}
	return fixtures
}

func patchedWireHeaders(headers http.Header) map[string][]string {
	normalized := make(map[string][]string, len(headers))
	for name, values := range headers {
		values = append([]string(nil), values...)
		sort.Strings(values)
		normalized[strings.ToLower(name)] = values
	}
	return normalized
}

func patchedWireCapture(req *http.Request, name string) (stockWireFixture, error) {
	var body []byte
	var errRead error
	if req.Body != nil {
		body, errRead = io.ReadAll(req.Body)
		if errRead != nil {
			return stockWireFixture{}, fmt.Errorf("read %s request body: %w", name, errRead)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return stockWireFixture{
		Name:    name,
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: patchedWireHeaders(req.Header),
		Body:    string(body),
	}, nil
}

func patchedWireContext(requestID string, rt http.RoundTripper) context.Context {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ginCtx.Request.Header.Set("Authorization", "Bearer ordinary-key")
	ginCtx.Request.Header.Set("User-Agent", "stock-wire-fixture/1.0")
	ginCtx.Request.Header.Set("X-Client-Request-Id", requestID)
	ginCtx.Set("userApiKey", "ordinary-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	return context.WithValue(ctx, "cliproxy.roundtripper", codexOAuthRoundTripFunc(rt.RoundTrip))
}

func patchedWireFixtureConfig() *config.Config {
	return &config.Config{
		CodexOAuthBaseURL:      "https://edge.example.test/codex",
		CodexOAuthHeaders:      map[string]string{"x-edgee-api-key": "edge-key"},
		CodexOAuthRouteAPIKeys: []string{"route-key"},
		SDKConfig:              config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll},
	}
}

func patchedWireAuth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "account-1",
		},
	}
}

func patchedWireRequest() cliproxyexecutor.Request {
	return cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":"hello"}`),
	}
}

func patchedWireOptions() cliproxyexecutor.Options {
	return cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")}
}

func capturePatchedUnmarkedWire(t *testing.T) stockWireFixtureSet {
	t.Helper()
	cfg := patchedWireFixtureConfig()
	auth := patchedWireAuth()
	fixtures := make([]stockWireFixture, 0, 5)

	var responses stockWireFixture
	responsesRT := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		responses, errCapture = patchedWireCapture(req, "responses_post")
		if errCapture != nil {
			return nil, errCapture
		}
		return codexOAuthCompletedResponse(req), nil
	})
	if _, errExecute := NewCodexExecutor(cfg).Execute(patchedWireContext("responses-post", responsesRT), auth, patchedWireRequest(), patchedWireOptions()); errExecute != nil {
		t.Fatalf("Execute responses POST: %v", errExecute)
	}
	responses.Outcome = "ok"
	fixtures = append(fixtures, responses)

	var stream stockWireFixture
	streamRT := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		stream, errCapture = patchedWireCapture(req, "sse_stream_request")
		if errCapture != nil {
			return nil, errCapture
		}
		return codexOAuthCompletedResponse(req), nil
	})
	streamResult, errStream := NewCodexExecutor(cfg).ExecuteStream(patchedWireContext("sse-stream", streamRT), auth, patchedWireRequest(), patchedWireOptions())
	if errStream != nil {
		t.Fatalf("ExecuteStream: %v", errStream)
	}
	for chunk := range streamResult.Chunks {
		if chunk.Err != nil {
			t.Fatalf("ExecuteStream chunk: %v", chunk.Err)
		}
	}
	stream.Outcome = "ok"
	fixtures = append(fixtures, stream)

	countTrap := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("count-tokens unexpectedly made outbound request to %s", req.URL.String())
	})
	countResponse, errCount := NewCodexExecutor(cfg).CountTokens(patchedWireContext("count-tokens", countTrap), auth, patchedWireRequest(), patchedWireOptions())
	if errCount != nil {
		t.Fatalf("CountTokens: %v", errCount)
	}
	fixtures = append(fixtures, stockWireFixture{
		Name:    "count_tokens",
		Headers: map[string][]string{},
		Outcome: "local:" + string(countResponse.Payload),
	})

	var query stockWireFixture
	queryRT := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		query, errCapture = patchedWireCapture(req, "query_bearing_url")
		if errCapture != nil {
			return nil, errCapture
		}
		return &http.Response{
			StatusCode: http.StatusNoContent,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader("")),
			Request:    req,
		}, nil
	})
	queryRequest, errNewQueryRequest := http.NewRequest(http.MethodPost, codexDefaultBaseURL+"/responses?include=usage&cursor=abc", strings.NewReader(`{"query":"kept"}`))
	if errNewQueryRequest != nil {
		t.Fatalf("create query-bearing request: %v", errNewQueryRequest)
	}
	queryResponse, errQuery := NewCodexExecutor(cfg).HttpRequest(patchedWireContext("query-bearing", queryRT), auth, queryRequest)
	if errQuery != nil {
		t.Fatalf("HttpRequest query-bearing URL: %v", errQuery)
	}
	if errClose := queryResponse.Body.Close(); errClose != nil {
		t.Fatalf("close query-bearing response: %v", errClose)
	}
	query.Outcome = "status:204"
	fixtures = append(fixtures, query)

	var errorPath stockWireFixture
	errorRT := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		errorPath, errCapture = patchedWireCapture(req, "upstream_error")
		if errCapture != nil {
			return nil, errCapture
		}
		return &http.Response{
			StatusCode: http.StatusTooManyRequests,
			Header:     http.Header{"Content-Type": {"application/json"}},
			Body:       io.NopCloser(strings.NewReader(`{"error":{"message":"fixture rate limit","type":"rate_limit_error"}}`)),
			Request:    req,
		}, nil
	})
	_, errExecute := NewCodexExecutor(cfg).Execute(patchedWireContext("upstream-error", errorRT), auth, patchedWireRequest(), patchedWireOptions())
	if errExecute == nil {
		t.Fatal("Execute upstream error returned nil error")
	}
	errorPath.Outcome = "error:" + errExecute.Error()
	fixtures = append(fixtures, errorPath)

	return stockWireFixtureSet{
		StockTag:    "v7.2.62",
		StockCommit: patchedStockWireFixtureCommit,
		Fixtures:    fixtures,
	}
}

func TestCodexExecutorUnmarkedWireMatchesStockV7_2_62(t *testing.T) {
	want := loadStockWireFixtures(t)
	got := capturePatchedUnmarkedWire(t)
	if !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Fatalf("unmarked wire differs from stock v7.2.62\nwant:\n%s\ngot:\n%s", wantJSON, gotJSON)
	}
	for _, fixture := range got.Fixtures {
		if strings.Contains(strings.ToLower(fixture.URL), "edgee") || strings.Contains(strings.ToLower(fixture.Body), "edgee") {
			t.Fatalf("fixture %q leaked override routing into unmarked wire", fixture.Name)
		}
		for name := range fixture.Headers {
			if strings.HasPrefix(name, "x-edgee-") {
				t.Fatalf("fixture %q contains override-only header %q", fixture.Name, name)
			}
		}
	}
}
