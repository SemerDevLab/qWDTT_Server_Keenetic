package qwdtt

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/curve25519"
)

func generateWGKeyPair() (string, string, error) {
	var p [32]byte
	if _, e := rand.Read(p[:]); e != nil {
		return "", "", e
	}
	p[0] &= 248
	p[31] &= 127
	p[31] |= 64
	pub, e := curve25519.X25519(p[:], curve25519.Basepoint)
	if e != nil {
		return "", "", e
	}
	return base64.StdEncoding.EncodeToString(p[:]), base64.StdEncoding.EncodeToString(pub), nil
}
func buildClientWGConfig(serverPublic, clientPrivate, clientIP, clientPort string) string {
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = 1.1.1.1\nMTU = 1280\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:%s\nPersistentKeepalive = 25\n", clientPrivate, clientIP, serverPublic, clientPort)
}
