package qwdtt

import (
	"context"
	"fmt"
)

func ApplyPolicy(ctx context.Context, r CommandRunner, c RoutingConfig) error {
	if r == nil {
		return fmt.Errorf("policy runner is nil")
	}
	// qWDTT server always exposes the full tunnel, including LAN resources.
	// Keep this no-op hook for compatibility with older configuration files.
	_ = ctx
	_ = c
	return nil
}
