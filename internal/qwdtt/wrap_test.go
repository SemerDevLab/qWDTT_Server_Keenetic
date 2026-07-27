package qwdtt

import "testing"

func TestWrapRoundTrip(t *testing.T) {
	key, _ := DeriveWrapKey("secret")
	src := []byte("wireguard datagram")
	wire, err := WrapPacket(key, src, WrapConfig{SSRC: 42, PayloadType: 111, PaddingMax: 8}, NewWrapState())
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 128)
	n, err := UnwrapPacket(key, wire, dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(dst[:n]) != string(src) {
		t.Fatalf("payload mismatch")
	}
}
