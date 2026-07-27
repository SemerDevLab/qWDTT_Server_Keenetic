package qwdtt

import "testing"

func TestDTLSConfigValidation(t *testing.T) {
	if err := (DTLSConfig{}).validate(); err == nil {
		t.Fatal("expected validation error")
	}
	if (DTLSConfig{Address: "127.0.0.1:1", Password: "x", Identity: "wdtt"}).serverConfig() == nil {
		t.Fatal("invalid DTLS config")
	}
}
