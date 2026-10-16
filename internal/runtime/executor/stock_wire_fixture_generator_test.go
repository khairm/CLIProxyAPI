//go:build stockwirefixture

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
	"sort"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

const stockWireFixtureCommit = "3554b63721aac9b4202bf2ef88ba7a82b4e5caf8"

type stockWireGeneratorRoundTripper func(*http.Request) (*http.Response, error)

func (f stockWireGeneratorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type stockWireGeneratorFixture struct {
	Name    string              `json:"name"`
	Method  string              `json:"method"`
	URL     string              `json:"url"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	Outcome string              `json:"outcome"`
}

type stockWireGeneratorFixtureSet struct {
	StockTag    string                      `json:"stock_tag"`
	StockCommit string                      `json:"stock_commit"`
	Fixtures    []stockWireGeneratorFixture `json:"fixtures"`
}

func stockWireGeneratorHeaders(headers http.Header) map[string][]string {
	normalized := make(map[string][]string, len(headers))
	for name, values := range headers {
		values = append([]string(nil), values...)
		sort.Strings(values)
		normalized[strings.ToLower(name)] = values
	}
	return normalized
}

func stockWireGeneratorCapture(req *http.Request, name string) (stockWireGeneratorFixture, error) {
	var body []byte
	var errRead error
	if req.Body != nil {
		body, errRead = io.ReadAll(req.Body)
		if errRead != nil {
			return stockWireGeneratorFixture{}, fmt.Errorf("read %s request body: %w", name, errRead)
		}
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return stockWireGeneratorFixture{
		Name:    name,
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: stockWireGeneratorHeaders(req.Header),
		Body:    string(body),
	}, nil
}

func stockWireGeneratorContext(requestID string, rt http.RoundTripper) context.Context {
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	ginCtx.Request.Header.Set("Authorization", "Bearer ordinary-key")
	ginCtx.Request.Header.Set("User-Agent", "stock-wire-fixture/1.0")
	ginCtx.Request.Header.Set("X-Client-Request-Id", requestID)
	ginCtx.Set("userApiKey", "ordinary-key")
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	return context.WithValue(ctx, "cliproxy.roundtripper", rt)
}

func stockWireGeneratorAuth() *cliproxyauth.Auth {
	return &cliproxyauth.Auth{
		Provider: "codex",
		Metadata: map[string]any{
			"access_token": "oauth-token",
			"account_id":   "account-1",
		},
	}
}

func stockWireGeneratorCompletedResponse(req *http.Request) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/event-stream"}},
		Body: io.NopCloser(strings.NewReader(
			"data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"completed\",\"output\":[],\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n",
		)),
		Request: req,
	}
}

func stockWireGeneratorRequest() cliproxyexecutor.Request {
	return cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(`{"model":"gpt-5-codex","input":"hello"}`),
	}
}

func stockWireGeneratorOptions() cliproxyexecutor.Options {
	return cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("openai-response")}
}

const stockWireGeneratorTerminalDelta = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"par\"}\n\n"

// 200 streams that end without response.completed. Must match patchedWireTerminalFixtures.
var stockWireGeneratorTerminalFixtures = []struct{ name, sse string }{
	{"terminal_error_event", stockWireGeneratorTerminalDelta +
		"data: {\"type\":\"error\",\"error\":{\"type\":\"invalid_request\",\"code\":\"cyber_policy\",\"message\":\"blocked\",\"param\":null},\"sequence_number\":3}\n\n"},
	{"terminal_response_failed", stockWireGeneratorTerminalDelta +
		"data: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"invalid_prompt\",\"message\":\"blocked\"}}}\n\n"},
	{"terminal_response_incomplete", stockWireGeneratorTerminalDelta +
		"data: {\"type\":\"response.incomplete\",\"response\":{\"id\":\"resp_1\",\"object\":\"response\",\"status\":\"incomplete\",\"output\":[],\"incomplete_details\":{\"reason\":\"content_filter\"},\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n"},
	{"stream_closed_no_completed", stockWireGeneratorTerminalDelta},
}

func stockWireGeneratorRun(t *testing.T) stockWireGeneratorFixtureSet {
	t.Helper()
	cfg := &config.Config{SDKConfig: config.SDKConfig{DisableImageGeneration: config.DisableImageGenerationAll}}
	auth := stockWireGeneratorAuth()
	fixtures := make([]stockWireGeneratorFixture, 0, 5)

	var responses stockWireGeneratorFixture
	responsesRT := stockWireGeneratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		responses, errCapture = stockWireGeneratorCapture(req, "responses_post")
		if errCapture != nil {
			return nil, errCapture
		}
		return stockWireGeneratorCompletedResponse(req), nil
	})
	if _, errExecute := NewCodexExecutor(cfg).Execute(stockWireGeneratorContext("responses-post", responsesRT), auth, stockWireGeneratorRequest(), stockWireGeneratorOptions()); errExecute != nil {
		t.Fatalf("Execute responses POST: %v", errExecute)
	}
	responses.Outcome = "ok"
	fixtures = append(fixtures, responses)

	var stream stockWireGeneratorFixture
	streamRT := stockWireGeneratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		stream, errCapture = stockWireGeneratorCapture(req, "sse_stream_request")
		if errCapture != nil {
			return nil, errCapture
		}
		return stockWireGeneratorCompletedResponse(req), nil
	})
	streamResult, errStream := NewCodexExecutor(cfg).ExecuteStream(stockWireGeneratorContext("sse-stream", streamRT), auth, stockWireGeneratorRequest(), stockWireGeneratorOptions())
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

	countTrap := stockWireGeneratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("count-tokens unexpectedly made outbound request to %s", req.URL.String())
	})
	countResponse, errCount := NewCodexExecutor(cfg).CountTokens(stockWireGeneratorContext("count-tokens", countTrap), auth, stockWireGeneratorRequest(), stockWireGeneratorOptions())
	if errCount != nil {
		t.Fatalf("CountTokens: %v", errCount)
	}
	fixtures = append(fixtures, stockWireGeneratorFixture{
		Name:    "count_tokens",
		Headers: map[string][]string{},
		Outcome: "local:" + string(countResponse.Payload),
	})

	var query stockWireGeneratorFixture
	queryRT := stockWireGeneratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		query, errCapture = stockWireGeneratorCapture(req, "query_bearing_url")
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
	queryRequest, errNewQueryRequest := http.NewRequest(http.MethodPost, "https://chatgpt.com/backend-api/codex/responses?include=usage&cursor=abc", strings.NewReader(`{"query":"kept"}`))
	if errNewQueryRequest != nil {
		t.Fatalf("create query-bearing request: %v", errNewQueryRequest)
	}
	queryResponse, errQuery := NewCodexExecutor(cfg).HttpRequest(stockWireGeneratorContext("query-bearing", queryRT), auth, queryRequest)
	if errQuery != nil {
		t.Fatalf("HttpRequest query-bearing URL: %v", errQuery)
	}
	if errClose := queryResponse.Body.Close(); errClose != nil {
		t.Fatalf("close query-bearing response: %v", errClose)
	}
	query.Outcome = "status:204"
	fixtures = append(fixtures, query)

	var errorPath stockWireGeneratorFixture
	errorRT := stockWireGeneratorRoundTripper(func(req *http.Request) (*http.Response, error) {
		var errCapture error
		errorPath, errCapture = stockWireGeneratorCapture(req, "upstream_error")
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
	_, errExecute := NewCodexExecutor(cfg).Execute(stockWireGeneratorContext("upstream-error", errorRT), auth, stockWireGeneratorRequest(), stockWireGeneratorOptions())
	if errExecute == nil {
		t.Fatal("Execute upstream error returned nil error")
	}
	errorPath.Outcome = "error:" + errExecute.Error()
	fixtures = append(fixtures, errorPath)

	for _, terminal := range stockWireGeneratorTerminalFixtures {
		var captured stockWireGeneratorFixture
		terminalRT := stockWireGeneratorRoundTripper(func(req *http.Request) (*http.Response, error) {
			var errCapture error
			captured, errCapture = stockWireGeneratorCapture(req, terminal.name)
			if errCapture != nil {
				return nil, errCapture
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"text/event-stream"}},
				Body:       io.NopCloser(strings.NewReader(terminal.sse)),
				Request:    req,
			}, nil
		})
		_, errTerminal := NewCodexExecutor(cfg).Execute(stockWireGeneratorContext(terminal.name, terminalRT), auth, stockWireGeneratorRequest(), stockWireGeneratorOptions())
		if errTerminal == nil {
			t.Fatalf("Execute %s returned nil error", terminal.name)
		}
		captured.Outcome = "error:" + errTerminal.Error()
		fixtures = append(fixtures, captured)
	}

	return stockWireGeneratorFixtureSet{
		StockTag:    "v7.2.62",
		StockCommit: stockWireFixtureCommit,
		Fixtures:    fixtures,
	}
}

// TestGenerateStockWireFixtures is run only after this file is copied into a
// detached v7.2.62 worktree. The checked-in JSON is therefore produced by the
// stock executor, not by the patched executor under test.
func TestGenerateStockWireFixtures(t *testing.T) {
	outputPath := strings.TrimSpace(os.Getenv("STOCK_WIRE_FIXTURE_OUTPUT"))
	if outputPath == "" {
		t.Fatal("STOCK_WIRE_FIXTURE_OUTPUT is required")
	}
	fixtures := stockWireGeneratorRun(t)
	data, errMarshal := json.MarshalIndent(fixtures, "", "  ")
	if errMarshal != nil {
		t.Fatalf("marshal fixtures: %v", errMarshal)
	}
	data = append(data, '\n')
	if errWrite := os.WriteFile(outputPath, data, 0o644); errWrite != nil {
		t.Fatalf("write fixtures: %v", errWrite)
	}
}
