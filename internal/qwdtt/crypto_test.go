package qwdtt

import "testing"

func TestDeriveWrapKeyDeterministic(t *testing.T) {
	a, err := DeriveWrapKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveWrapKey("test-password")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) || len(a) != 32 {
		t.Fatalf("invalid derived key")
	}
	if WrapKeyID("test-password") == WrapKeyID("other-password") {
		t.Fatal("key IDs collide")
	}
}
