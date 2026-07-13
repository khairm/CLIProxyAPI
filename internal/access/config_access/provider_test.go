package configaccess

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProviderReportsTrustedBearerMetadata(t *testing.T) {
	tests := []struct {
		name               string
		configureRequest   func(*http.Request)
		wantSource         string
		wantCredentialKind string
	}{
		{
			name: "bearer authorization",
			configureRequest: func(request *http.Request) {
				request.Header.Set("Authorization", "Bearer route-key")
			},
			wantSource:         "authorization",
			wantCredentialKind: "bearer",
		},
		{
			name: "case insensitive bearer authorization",
			configureRequest: func(request *http.Request) {
				request.Header.Set("Authorization", "bEaReR route-key")
			},
			wantSource:         "authorization",
			wantCredentialKind: "bearer",
		},
		{
			name: "raw authorization remains supported but is not a bearer",
			configureRequest: func(request *http.Request) {
				request.Header.Set("Authorization", "route-key")
			},
			wantSource: "authorization",
		},
		{
			name: "x-api-key is not a bearer",
			configureRequest: func(request *http.Request) {
				request.Header.Set("X-Api-Key", "route-key")
			},
			wantSource: "x-api-key",
		},
		{
			name: "query key is not a bearer",
			configureRequest: func(request *http.Request) {
				query := request.URL.Query()
				query.Set("key", "route-key")
				request.URL.RawQuery = query.Encode()
			},
			wantSource: "query-key",
		},
	}

	provider := newProvider("", []string{"route-key"})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			tt.configureRequest(request)

			result, authErr := provider.Authenticate(context.Background(), request)
			if authErr != nil {
				t.Fatalf("Authenticate() error = %v", authErr)
			}
			if result == nil || result.Principal != "route-key" {
				t.Fatalf("Authenticate() result = %#v, want route-key principal", result)
			}
			if got := result.Metadata["source"]; got != tt.wantSource {
				t.Fatalf("source = %q, want %q", got, tt.wantSource)
			}
			if got := result.Metadata["credential-kind"]; got != tt.wantCredentialKind {
				t.Fatalf("credential-kind = %q, want %q", got, tt.wantCredentialKind)
			}
		})
	}
}
