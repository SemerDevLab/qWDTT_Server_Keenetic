package qwdtt

import (
	"context"
	"fmt"
)

type TunBackend struct {
	Runner CommandRunner
	DryRun bool
}

func (t TunBackend) Create(ctx context.Context, name, address string) error {
	if t.Runner == nil {
		return fmt.Errorf("tun runner is nil")
	}
	if name == "" {
		name = "wdtt0"
	}
	if address == "" {
		return fmt.Errorf("tun address is required")
	}
	commands := [][]string{{"tuntap", "add", "dev", name, "mode", "tun"}, {"addr", "replace", address, "dev", name}, {"link", "set", "dev", name, "up"}}
	for _, args := range commands {
		if !t.DryRun {
			if err := t.Runner.Run(ctx, "ip", args...); err != nil {
				return fmt.Errorf("create tun: %w", err)
			}
		}
	}
	return nil
}

func (t TunBackend) Remove(ctx context.Context, name string) error {
	if t.Runner == nil {
		return fmt.Errorf("tun runner is nil")
	}
	if name == "" {
		name = "wdtt0"
	}
	if t.DryRun {
		return nil
	}
	return t.Runner.Run(ctx, "ip", "link", "delete", name)
}
