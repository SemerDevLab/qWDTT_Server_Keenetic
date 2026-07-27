package qwdtt

import (
	"context"
	"fmt"
)

// CommandRunner isolates router shell execution from the routing logic.
type CommandRunner interface {
	Run(context.Context, string, ...string) error
}

type Backend struct {
	Runner CommandRunner
	DryRun bool
}

// Apply creates the tunnel address and installs the requested routes.
// The actual WireGuard/DTLS transport owns the interface lifecycle; this
// backend only prepares the router's IP layer.
func (b Backend) Apply(ctx context.Context, cfg RoutingConfig, address, gateway string) error {
	if b.Runner == nil {
		return fmt.Errorf("routing backend runner is nil")
	}
	if address == "" || gateway == "" {
		return fmt.Errorf("tunnel address and gateway are required")
	}
	rules, err := BuildRules(cfg)
	if err != nil {
		return err
	}
	device := cfg.Interface
	if device == "" {
		device = "wdtt0"
	}
	commands := []struct {
		name string
		args []string
	}{
		{"ip", []string{"addr", "replace", address, "dev", device}},
		{"ip", []string{"link", "set", "dev", device, "up"}},
	}
	for _, rule := range rules {
		if rule.Kind == "default" {
			commands = append(commands, struct {
				name string
				args []string
			}{"ip", []string{"route", "replace", "default", "via", gateway, "dev", device}})
			continue
		}
		commands = append(commands, struct {
			name string
			args []string
		}{"ip", []string{"route", "replace", rule.Target, "via", gateway, "dev", device}})
	}
	for _, command := range commands {
		if b.DryRun {
			continue
		}
		if err := b.Runner.Run(ctx, command.name, command.args...); err != nil {
			return fmt.Errorf("run %s %v: %w", command.name, command.args, err)
		}
	}
	return nil
}

func (b Backend) Remove(ctx context.Context, cfg RoutingConfig) error {
	if b.Runner == nil {
		return fmt.Errorf("routing backend runner is nil")
	}
	device := cfg.Interface
	if device == "" {
		device = "wdtt0"
	}
	if b.DryRun {
		return nil
	}
	if err := b.Runner.Run(ctx, "ip", "link", "set", "dev", device, "down"); err != nil {
		return fmt.Errorf("stop %s: %w", device, err)
	}
	return nil
}
