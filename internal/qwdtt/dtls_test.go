package qwdtt

import "testing"

func TestDTLSConfigValidation(t *testing.T) {
	if err := (DTLSConfig{}).validate(); err == nil {
		t.Fatal("expected validation error")
	}
	if cfg, err := (DTLSConfig{Address: "127.0.0.1:1", Password: "x", Identity: "wdtt"}).serverConfig(); err != nil || cfg == nil {
		t.Fatal("invalid DTLS config")
	}
}
