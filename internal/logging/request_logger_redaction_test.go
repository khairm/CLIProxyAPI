package logging

import (
	"strings"
	"testing"
)

func TestFormatRequestInfoFullyRedactsAuthorizationAndEdgeeHeaders(t *testing.T) {
	secrets := map[string]struct {
		value      string
		credential string
	}{
		"Authorization":      {value: "Bearer AZQJ-routed-bearer-WXVU", credential: "AZQJ-routed-bearer-WXVU"},
		"X-Edgee-Api-Key":    {value: "BKVR-edgee-api-key-TSRP", credential: "BKVR-edgee-api-key-TSRP"},
		"X-Edgee-Session-Id": {value: "065e0091-7f30-4f0b-a0ed-3e45e2bb1124", credential: "065e0091-7f30-4f0b-a0ed-3e45e2bb1124"},
	}
	headers := make(map[string][]string, len(secrets))
	for name, secret := range secrets {
		headers[name] = []string{secret.value}
	}

	logged := (&FileRequestLogger{}).formatRequestInfo("/v1/responses", "POST", headers, nil, "http", "http", false)
	for name, secret := range secrets {
		for _, fragment := range []string{secret.credential, secret.credential[:4], secret.credential[len(secret.credential)-4:]} {
			if strings.Contains(logged, fragment) {
				t.Fatalf("request log contains %s secret fragment %q:\n%s", name, fragment, logged)
			}
		}
		if !strings.Contains(logged, name+": [REDACTED]") {
			t.Fatalf("request log does not fully redact %s:\n%s", name, logged)
		}
	}
}
