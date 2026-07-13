package main

import (
	"net/url"
	"testing"
)

func TestCodexModelsURLUsesStockRoute(t *testing.T) {
	rawURL, errURL := codexModelsURL("test-version")
	if errURL != nil {
		t.Fatalf("codexModelsURL() error = %v", errURL)
	}
	parsed, errParse := url.Parse(rawURL)
	if errParse != nil {
		t.Fatalf("parse models URL: %v", errParse)
	}
	if got := parsed.Scheme + "://" + parsed.Host + parsed.Path; got != codexModelsBaseURL+codexModelsPath {
		t.Fatalf("models URL = %q, want stock route %q", got, codexModelsBaseURL+codexModelsPath)
	}
	if got := parsed.Query().Get("client_version"); got != "test-version" {
		t.Fatalf("client_version = %q, want test-version", got)
	}
}
