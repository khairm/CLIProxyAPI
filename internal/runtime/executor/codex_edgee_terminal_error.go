package executor

import (
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Edgee fork: Edgee-routed Execute returns the real terminal upstream error instead of stock's 408.
func codexEdgeeTerminalErr(eventData []byte) (statusErr, bool) {
	var body []byte
	switch gjson.GetBytes(eventData, "type").String() {
	case "error":
		if body = codexTerminalErrorBody(eventData, "error"); len(body) == 0 {
			body = codexTerminalTopLevelErrorBody(eventData)
		}
	case "response.failed":
		if body = codexTerminalErrorBody(eventData, "response.error"); len(body) == 0 {
			body = codexTerminalErrorBody(eventData, "error")
		}
	}
	if len(body) == 0 {
		return statusErr{}, false
	}
	status, anthropicType := codexEdgeeErrorClass(body)
	message := strings.TrimSpace(gjson.GetBytes(body, "error.message").String())
	if message == "" {
		message = string(eventData)
	}
	out, _ := sjson.SetBytes([]byte(`{"error":{}}`), "error.type", anthropicType)
	out, _ = sjson.SetBytes(out, "error.message", message)
	return statusErr{code: status, msg: string(out)}, true
}

// Code first, then type, else 500.
func codexEdgeeErrorClass(body []byte) (int, string) {
	switch strings.TrimSpace(gjson.GetBytes(body, "error.code").String()) {
	case "invalid_prompt", "cyber_policy", "bio_policy", "misalignment_policy_violation",
		"usage_not_included", "insufficient_quota", "credit_balance_exhausted",
		"organization_spend_limit_exceeded", "project_spend_limit_exceeded":
		return http.StatusBadRequest, "invalid_request_error"
	case "rate_limit_exceeded", "slow_down":
		return http.StatusTooManyRequests, "rate_limit_error"
	}
	switch strings.TrimSpace(gjson.GetBytes(body, "error.type").String()) {
	case "invalid_request", "invalid_request_error":
		return http.StatusBadRequest, "invalid_request_error"
	case "rate_limit_error":
		return http.StatusTooManyRequests, "rate_limit_error"
	}
	return http.StatusInternalServerError, "api_error"
}
