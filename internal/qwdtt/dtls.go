package qwdtt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
)

// DTLSConfig describes the transport endpoint. The PSK identity is kept
// explicit because the VPS protocol uses the WDTT password as authentication
// material while WRAP provides packet-level authentication.
type DTLSConfig struct {
	Address  string
	Password string
	Identity string
	Timeout  time.Duration
	Server   bool
	Logs     *LogBook
}

type DTLSProfile struct {
	ID       string
	Password string
}

type profileListener struct {
	net.Listener
	wrapped *wrappedListener
}

func (l *profileListener) ProfileID(addr net.Addr) string { return l.wrapped.ProfileID(addr) }

func (c DTLSConfig) validate() error {
	if c.Address == "" || c.Password == "" {
		return fmt.Errorf("dtls address and password are required")
	}
	if c.Identity == "" {
		return fmt.Errorf("dtls PSK identity is required")
	}
	return nil
}

func (c DTLSConfig) clientConfig() *dtls.Config {
	return &dtls.Config{InsecureSkipVerify: true, CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret}
}

func (c DTLSConfig) serverConfig() *dtls.Config {
	certificate, _ := selfsign.GenerateSelfSigned()
	return &dtls.Config{Certificates: []tls.Certificate{certificate}, CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, ExtendedMasterSecret: dtls.RequireExtendedMasterSecret}
}

func DialDTLS(ctx context.Context, c DTLSConfig) (net.Conn, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", c.Address)
	if err != nil {
		return nil, err
	}
	local, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	raw := net.PacketConn(local)
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	conn, err := dtls.Client(raw, remote, c.clientConfig())
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func ListenDTLS(c DTLSConfig) (net.Listener, error) {
	return ListenProfileDTLS(c, []DTLSProfile{{ID: "default", Password: c.Password}})
}

func ListenProfileDTLS(c DTLSConfig, profiles []DTLSProfile) (*profileListener, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	addr, err := net.ResolveUDPAddr("udp", c.Address)
	if err != nil {
		return nil, err
	}
	keys := make([]wrapIdentity, 0, len(profiles))
	for _, profile := range profiles {
		key, keyErr := DeriveWrapKey(profile.Password)
		if keyErr != nil {
			return nil, keyErr
		}
		keys = append(keys, wrapIdentity{id: profile.ID, key: key})
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one DTLS profile is required")
	}
	inner, err := newWrappedListener(addr, keys, c.Logs)
	if err != nil {
		return nil, err
	}
	listener, err := dtls.NewListenerWithOptions(
		inner,
		dtls.WithCertificates(c.serverConfig().Certificates[0]),
		dtls.WithExtendedMasterSecret(dtls.RequireExtendedMasterSecret),
		dtls.WithCipherSuites(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
		// Keep this aligned with the original VPS server. The official client
		// negotiates DTLS Connection IDs for TURN paths that may be rebound.
		dtls.WithConnectionIDGenerator(dtls.RandomCIDGenerator(8)),
		dtls.WithMTU(1100),
	)
	if err != nil {
		_ = inner.Close()
		return nil, err
	}
	return &profileListener{Listener: listener, wrapped: inner}, nil
}
