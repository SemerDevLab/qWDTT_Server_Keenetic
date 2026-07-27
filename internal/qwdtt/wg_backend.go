package qwdtt

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type OSRunner struct{}

func (OSRunner) Run(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(output))
	}
	return nil
}

type WGBackend struct {
	Runner        CommandRunner
	Interface     string
	ServerPrivate string
	ServerPublic  string
	ListenPort    int
	Address       string
}

func (b WGBackend) Setup(ctx context.Context) error {
	if b.Runner == nil {
		return fmt.Errorf("wireguard runner is nil")
	}
	if b.Interface == "" {
		b.Interface = "wdtt0"
	}
	if b.ListenPort == 0 {
		b.ListenPort = 56001
	}
	if b.Address == "" {
		b.Address = "10.66.66.1/16"
	}
	// A previous process may have left the interface and obsolete peers
	// behind. Recreate this service-owned interface so peers and listen-port
	// state cannot accumulate across restarts.
	_ = b.Runner.Run(ctx, "ip", "link", "del", b.Interface)
	if err := b.Runner.Run(ctx, "ip", "link", "add", b.Interface, "type", "wireguard"); err != nil {
		return err
	}
	if e := b.Runner.Run(ctx, "wg", "set", b.Interface, "private-key", b.ServerPrivate, "listen-port", fmt.Sprint(b.ListenPort)); e != nil {
		return e
	}
	if e := b.Runner.Run(ctx, "ip", "addr", "replace", b.Address, "dev", b.Interface); e != nil {
		return e
	}
	return b.Runner.Run(ctx, "ip", "link", "set", "dev", b.Interface, "up")
}
func (b WGBackend) AddPeer(ctx context.Context, pub, ip string) error {
	return b.Runner.Run(ctx, "wg", "set", b.Interface, "peer", pub, "allowed-ips", ip+"/32", "persistent-keepalive", "25")
}
func ensureKeyPair(dir string) (string, string, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return "", "", e
	}
	priv := filepath.Join(dir, "server.key")
	pub := filepath.Join(dir, "server.pub")
	if p, e := os.ReadFile(priv); e == nil {
		if q, e2 := os.ReadFile(pub); e2 == nil {
			return string(p), string(q), nil
		}
	}
	a, b, e := generateWGKeyPair()
	if e != nil {
		return "", "", e
	}
	if e = os.WriteFile(priv, []byte(a), 0600); e != nil {
		return "", "", e
	}
	if e = os.WriteFile(pub, []byte(b), 0644); e != nil {
		return "", "", e
	}
	return a, b, nil
}
