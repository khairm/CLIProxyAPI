package config

import (
	"strings"
	"testing"
)

func TestParseConfigBytesRejectsMalformedProxyURLs(t *testing.T) {
	t.Parallel()
	for name, yaml := range map[string]string{
		"global":    "proxy-url: sock5://127.0.0.1:1080\n",
		"codex key": "codex-api-key:\n  - api-key: k\n    base-url: https://example.com\n    proxy-url: \"http://\"\n",
		"compat entry": "openai-compatibility:\n  - name: x\n    base-url: https://example.com\n" +
			"    api-key-entries:\n      - api-key: k\n        proxy-url: ftp://p:21\n",
	} {
		if _, err := ParseConfigBytes([]byte(yaml)); err == nil || !strings.Contains(err.Error(), "proxy-url") {
			t.Fatalf("%s: err = %v, want a proxy-url error", name, err)
		}
	}
	for _, ok := range []string{"", "direct", "none", "http://127.0.0.1:18319", "socks5h://u:p@host:1080"} {
		if _, err := ParseConfigBytes([]byte("proxy-url: \"" + ok + "\"\n")); err != nil {
			t.Fatalf("proxy-url %q rejected: %v", ok, err)
		}
	}
}
