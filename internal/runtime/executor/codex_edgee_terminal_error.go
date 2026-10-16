package executor

import (
	"net/http"
	"strings"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// Edgee fork: Edgee-routed Execute returns the real terminal upstream error instead of stock's 408.
// It returns the error to keep; a detail-free event never replaces a stored error.
func codexEdgeeTerminalErr(eventData []byte, stored error) error {
	eventType := gjson.GetBytes(eventData, "type").String()
	var body []byte
	switch eventType {
	case "error":
		if body = codexTerminalErrorBody(eventData, "error"); len(body) == 0 {
			body = codexTerminalTopLevelErrorBody(eventData)
		}
	case "response.failed":
		if body = codexTerminalErrorBody(eventData, "response.error"); len(body) == 0 {
			body = codexTerminalErrorBody(eventData, "error")
		}
	default:
		return stored
	}
	// The body helpers fill an empty message from code, then type.
	message := strings.TrimSpace(gjson.GetBytes(body, "error.message").String())
	if message == "" {
		if stored != nil {
			return stored
		}
		message = "upstream " + eventType + " with no error details"
	}
	status, anthropicType := codexEdgeeErrorClass(body)
	out, _ := sjson.SetBytes([]byte(`{"error":{}}`), "error.type", anthropicType)
	out, _ = sjson.SetBytes(out, "error.message", message)
	return statusErr{code: status, msg: string(out)}
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

// Edgee fork: response.incomplete keeps only finished function calls, and only after max_output_tokens.
func codexEdgeeFilterIncompleteFunctionCalls(eventData []byte) []byte {
	output := gjson.GetBytes(eventData, "response.output")
	if !output.IsArray() {
		return eventData
	}
	keepFinished := gjson.GetBytes(eventData, "response.incomplete_details.reason").String() == "max_output_tokens"
	items := output.Array()
	kept := make([]string, 0, len(items))
	for _, item := range items {
		if item.Get("type").String() != "function_call" || (keepFinished && codexEdgeeFunctionCallFinished(item)) {
			kept = append(kept, item.Raw)
		}
	}
	if len(kept) == len(items) {
		return eventData
	}
	out, _ := sjson.SetRawBytes(eventData, "response.output", rawJSONArray(kept))
	return out
}

func codexEdgeeFunctionCallFinished(item gjson.Result) bool {
	status := item.Get("status")
	return (!status.Exists() || status.String() == "completed") && gjson.Valid(item.Get("arguments").String())
}
