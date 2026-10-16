package executor

import (
	"net/http"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const (
	edgeeTerminalStock408     = "stream error: stream disconnected before completion: stream closed before response.completed"
	edgeeTerminalCyberMessage = "This request was blocked by our safety systems. Reason: Potentially unintended activity."
	edgeeTerminalCyberEvent   = `{"type":"error","error":{"type":"invalid_request","code":"cyber_policy","message":"` + edgeeTerminalCyberMessage + `","param":null},"sequence_number":3}`
	edgeeTerminalEmptyFailed  = `{"type":"response.failed","response":{"error":{}}}`
	edgeeTerminalPartialItem  = `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"partial"}]}`
	edgeeTerminalPartialDone  = `{"type":"response.output_item.done","output_index":0,"item":` + edgeeTerminalPartialItem + `}`
	edgeeTerminalClaudeBody   = `{"model":"gpt-5-codex","max_tokens":64,"messages":[{"role":"user","content":"hello"}]}`
	edgeeTerminalFinishedCall = `{"type":"function_call","status":"completed","call_id":"call_1","name":"Bash","arguments":"{\"command\":\"ls\"}"}`
	edgeeTerminalCutOffCall   = `{"type":"function_call","call_id":"call_2","name":"Bash","arguments":"{\"command\":\"rm -"}`
)

type edgeeTerminalCheck func(t *testing.T, resp cliproxyexecutor.Response, err error)

func edgeeTerminalIncomplete(reason string) string {
	return edgeeTerminalIncompleteWithOutput(reason, "")
}

func edgeeTerminalIncompleteWithOutput(reason, output string) string {
	return `{"type":"response.incomplete","response":{"id":"resp_1","object":"response","status":"incomplete","output":[` + output + `],"incomplete_details":{"reason":"` + reason + `"},"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`
}

func executeEdgeeTerminalCase(routed bool, events []string) (cliproxyexecutor.Response, error) {
	return executeEdgeeTerminalFormatCase(routed, sdktranslator.FormatClaude, edgeeTerminalClaudeBody, events)
}

func executeEdgeeTerminalFormatCase(routed bool, format sdktranslator.Format, payload string, events []string) (cliproxyexecutor.Response, error) {
	var sse strings.Builder
	for _, event := range append([]string{
		`{"type":"response.created","response":{"id":"resp_1","object":"response","status":"in_progress","output":[]}}`,
		`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"par"}`,
	}, events...) {
		sse.WriteString("data: " + event + "\n\n")
	}
	rt := codexOAuthRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return codexOAuthSSEResponse(req, sse.String()), nil
	})
	ctx := codexOAuthExecutionContext("client-key", "edgee-terminal", routed, "", rt)
	return NewCodexExecutor(patchedWireFixtureConfig()).Execute(ctx, patchedWireAuth(), cliproxyexecutor.Request{
		Model:   "gpt-5-codex",
		Payload: []byte(payload),
	}, cliproxyexecutor.Options{SourceFormat: format})
}

func edgeeTerminalWantError(wantStatus int, wantMsg string) edgeeTerminalCheck {
	return func(t *testing.T, _ cliproxyexecutor.Response, err error) {
		t.Helper()
		assertStatusErr(t, err, wantStatus)
		if got := err.Error(); got != wantMsg {
			t.Fatalf("err = %s, want %s", got, wantMsg)
		}
	}
}

func edgeeTerminalWantPassthrough(wantStatus int, wantType, wantMessage string) edgeeTerminalCheck {
	return func(t *testing.T, _ cliproxyexecutor.Response, err error) {
		t.Helper()
		assertStatusErr(t, err, wantStatus)
		got := err.Error()
		if !gjson.Valid(got) {
			t.Fatalf("err is not JSON: %s", got)
		}
		if errType := gjson.Get(got, "error.type").String(); errType != wantType {
			t.Fatalf("error.type = %q, want %q; err=%s", errType, wantType, got)
		}
		if message := gjson.Get(got, "error.message").String(); message != wantMessage {
			t.Fatalf("error.message = %q, want %q", message, wantMessage)
		}
	}
}

func edgeeTerminalWantReply(wantStop, wantText string, wantCommands ...string) edgeeTerminalCheck {
	return func(t *testing.T, resp cliproxyexecutor.Response, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("err = %v, want reply", err)
		}
		if got := gjson.GetBytes(resp.Payload, "type").String(); got != "message" {
			t.Fatalf("type = %q, want message; payload=%s", got, resp.Payload)
		}
		if got := gjson.GetBytes(resp.Payload, "stop_reason").String(); got != wantStop {
			t.Fatalf("stop_reason = %q, want %q; payload=%s", got, wantStop, resp.Payload)
		}
		if got := gjson.GetBytes(resp.Payload, "content.0.text").String(); got != wantText {
			t.Fatalf("content.0.text = %q, want %q; payload=%s", got, wantText, resp.Payload)
		}
		tools := gjson.GetBytes(resp.Payload, `content.#(type=="tool_use")#`).Array()
		if len(tools) != len(wantCommands) {
			t.Fatalf("tool_use blocks = %d, want %d; payload=%s", len(tools), len(wantCommands), resp.Payload)
		}
		for i, tool := range tools {
			if got := tool.Get("input.command").String(); got != wantCommands[i] {
				t.Fatalf("tool_use %d input.command = %q, want %q", i, got, wantCommands[i])
			}
		}
	}
}

func TestCodexExecutorEdgeeTerminalErrorPassthrough(t *testing.T) {
	stock408 := edgeeTerminalWantError(http.StatusRequestTimeout, edgeeTerminalStock408)
	contextLength := edgeeTerminalWantError(http.StatusBadRequest, `{"error":{"message":"too long","type":"invalid_request_error","code":"context_too_large"}}`)

	cases := []struct {
		name     string
		events   []string
		unmarked edgeeTerminalCheck
		marked   edgeeTerminalCheck
	}{
		{"cyber block", []string{edgeeTerminalCyberEvent}, stock408, edgeeTerminalWantPassthrough(http.StatusBadRequest, "invalid_request_error", edgeeTerminalCyberMessage)},
		{"top-level error", []string{`{"type":"error","code":"invalid_prompt","message":"blocked"}`}, stock408, edgeeTerminalWantPassthrough(http.StatusBadRequest, "invalid_request_error", "blocked")},
		{"failed policy", []string{`{"type":"response.failed","response":{"error":{"code":"invalid_prompt","message":"blocked"}}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusBadRequest, "invalid_request_error", "blocked")},
		{"type only", []string{`{"type":"error","error":{"type":"invalid_request","code":"new_policy","message":"m"}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusBadRequest, "invalid_request_error", "m")},
		{"rate limit", []string{`{"type":"error","error":{"code":"rate_limit_exceeded","message":"slow"}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusTooManyRequests, "rate_limit_error", "slow")},
		{"slow_down", []string{`{"type":"error","error":{"code":"slow_down","message":"wait"}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusTooManyRequests, "rate_limit_error", "wait")},
		{"unknown code", []string{`{"type":"error","error":{"code":"server_is_overloaded","message":"busy"}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusInternalServerError, "api_error", "busy")},
		{"message only", []string{`{"type":"error","error":{"message":"edgee said no"}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusInternalServerError, "api_error", "edgee said no")},
		{"empty object", []string{edgeeTerminalEmptyFailed}, stock408, edgeeTerminalWantPassthrough(http.StatusInternalServerError, "api_error", "upstream response.failed with no error details")},
		{"failed without error field", []string{`{"type":"response.failed","response":{"status":"failed"}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusInternalServerError, "api_error", "upstream response.failed with no error details")},
		{"error then completed", []string{edgeeTerminalCyberEvent, edgeeTerminalPartialDone, `{"type":"response.completed","response":{"id":"resp_1","object":"response","status":"completed","output":[],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`}, edgeeTerminalWantReply("end_turn", "partial"), edgeeTerminalWantReply("end_turn", "partial")},
		{"error then failed", []string{edgeeTerminalCyberEvent, `{"type":"response.failed","response":{"error":{"code":"rate_limit_exceeded","message":"failed slow"}}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusTooManyRequests, "rate_limit_error", "failed slow")},
		{"error then failed without details", []string{edgeeTerminalCyberEvent, `{"type":"response.failed","response":{"error":null}}`}, stock408, edgeeTerminalWantPassthrough(http.StatusBadRequest, "invalid_request_error", edgeeTerminalCyberMessage)},
		{"error then incomplete", []string{edgeeTerminalCyberEvent, edgeeTerminalPartialDone, edgeeTerminalIncomplete("content_filter")}, stock408, edgeeTerminalWantReply("refusal", "partial")},
		{"incomplete filter", []string{edgeeTerminalPartialDone, edgeeTerminalIncomplete("content_filter")}, stock408, edgeeTerminalWantReply("refusal", "partial")},
		{"incomplete length", []string{edgeeTerminalPartialDone, edgeeTerminalIncomplete("max_output_tokens")}, stock408, edgeeTerminalWantReply("max_tokens", "partial")},
		{"incomplete populated output", []string{edgeeTerminalIncompleteWithOutput("max_output_tokens", edgeeTerminalPartialItem)}, stock408, edgeeTerminalWantReply("max_tokens", "partial")},
		{"incomplete truncated function_call", []string{edgeeTerminalIncompleteWithOutput("max_output_tokens", edgeeTerminalPartialItem+
			`,{"type":"function_call","status":"incomplete","call_id":"call_1","name":"Bash","arguments":"{\"command\":\"ls\"}"}`+
			","+edgeeTerminalCutOffCall)}, stock408, edgeeTerminalWantReply("max_tokens", "partial")},
		{"incomplete length keeps finished call", []string{edgeeTerminalIncompleteWithOutput("max_output_tokens", edgeeTerminalPartialItem+","+edgeeTerminalFinishedCall+","+edgeeTerminalCutOffCall)}, stock408, edgeeTerminalWantReply("tool_use", "partial", "ls")},
		{"incomplete filter drops finished call", []string{edgeeTerminalIncompleteWithOutput("content_filter", edgeeTerminalPartialItem+","+edgeeTerminalFinishedCall)}, stock408, edgeeTerminalWantReply("refusal", "partial")},
		{"incomplete length drops in_progress call", []string{edgeeTerminalIncompleteWithOutput("max_output_tokens", edgeeTerminalPartialItem+
			`,{"type":"function_call","status":"in_progress","call_id":"call_1","name":"Bash","arguments":"{\"command\":\"ls\"}"}`)}, stock408, edgeeTerminalWantReply("max_tokens", "partial")},
		{"stock context length", []string{`{"type":"error","error":{"code":"context_length_exceeded","message":"too long"}}`}, contextLength, contextLength},
		{"no terminal event", nil, stock408, stock408},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := executeEdgeeTerminalCase(false, tc.events)
			tc.unmarked(t, resp, err)
			resp, err = executeEdgeeTerminalCase(true, tc.events)
			tc.marked(t, resp, err)
		})
	}

	t.Run("non-claude incomplete", func(t *testing.T) {
		events := []string{edgeeTerminalPartialDone, edgeeTerminalIncomplete("max_output_tokens")}
		for _, routed := range []bool{false, true} {
			resp, err := executeEdgeeTerminalFormatCase(routed, sdktranslator.FormatOpenAIResponse, `{"model":"gpt-5-codex","input":"hello"}`, events)
			stock408(t, resp, err)
		}
	})
}
