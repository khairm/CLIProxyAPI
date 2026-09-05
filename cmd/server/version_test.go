package main

import "testing"

func TestEmbeddedVersion(t *testing.T) {
	if Version != "7.2.62+edgee.4" {
		t.Fatalf("Version = %q, want 7.2.62+edgee.4", Version)
	}
}
