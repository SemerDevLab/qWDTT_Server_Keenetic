package qwdtt

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Runtime owns the live server process behind the web control panel.
// Configuration changes are applied by restarting only the transport context;
// the HTTP control panel remains available while the server is disabled.
type Runtime struct {
	mu             sync.Mutex
	cfg            *Config
	path           string
	logs           *LogBook
	parent         context.Context
	cancel         context.CancelFunc
	run            bool
	gen            uint64
	traffic        *TrafficStats
	profileTraffic *ProfileTrafficTracker
	peers          *peerStore
}

func NewRuntime(cfg *Config, path string, logs *LogBook) *Runtime {
	return &Runtime{
		cfg:            cfg,
		path:           path,
		logs:           logs,
		traffic:        &TrafficStats{},
		profileTraffic: NewProfileTrafficTracker(),
		peers:          &peerStore{peers: make(map[string]clientPeer)},
	}
}

func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	r.parent = ctx
	r.mu.Unlock()
	return r.reconcile()
}

func (r *Runtime) Running() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.run
}

func (r *Runtime) Config() Config {
	r.mu.Lock()
	defer r.mu.Unlock()
	return *r.cfg
}

func (r *Runtime) ApplyConfig(cfg Config) error {
	cfg.NormalizeProfiles()
	if err := cfg.Validate(); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.path, append(b, '\n'), 0600); err != nil {
		return err
	}
	r.mu.Lock()
	*r.cfg = cfg
	r.mu.Unlock()
	return nil
}

// Update persists cfg and reconciles the transport with its Enabled state.
func (r *Runtime) Update(cfg Config) error {
	previous := r.Config()
	cfg.NormalizeProfiles()
	if err := r.ApplyConfig(cfg); err != nil {
		return err
	}
	if cfg.Enabled && !r.Running() {
		return r.reconcile()
	}
	if !transportRestartRequired(previous, cfg) {
		if cfg.Enabled {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := EnsureGlobalFirewallPolicies(ctx, OSRunner{}, cfg.Server.Profiles, cfg.Firewall); err != nil {
				return fmt.Errorf("apply profile policies without restart: %w", err)
			}
		}
		if r.logs != nil {
			r.logs.Add("INFO", "configuration applied without interrupting active connections")
		}
		return nil
	}
	return r.reconcile()
}

func transportRestartRequired(previous, next Config) bool {
	if previous.Enabled != next.Enabled ||
		previous.Mode != next.Mode ||
		previous.DataDir != next.DataDir ||
		previous.Server.ListenAddr != next.Server.ListenAddr ||
		previous.Server.DTLSPort != next.Server.DTLSPort ||
		previous.Server.WGPort != next.Server.WGPort ||
		previous.Server.Password != next.Server.Password ||
		previous.Server.Network != next.Server.Network ||
		previous.Routing.WAN != next.Routing.WAN {
		return true
	}
	if len(previous.Server.Profiles) != len(next.Server.Profiles) {
		return true
	}
	byID := make(map[string]ConnectionProfile, len(previous.Server.Profiles))
	for _, profile := range previous.Server.Profiles {
		byID[profile.ID] = profile
	}
	for _, profile := range next.Server.Profiles {
		old, ok := byID[profile.ID]
		if !ok ||
			old.Enabled != profile.Enabled ||
			old.ClientIP != profile.ClientIP {
			return true
		}
	}
	return false
}

func (r *Runtime) reconcile() error {
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.run = false
	cfg := *r.cfg
	parent := r.parent
	logs := r.logs
	if !cfg.Enabled {
		r.mu.Unlock()
		return nil
	}
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.gen++
	gen := r.gen
	r.run = true
	r.mu.Unlock()

	go func() {
		backoff := time.Second
		for {
			err := (Service{
				Config:         cfg,
				Logs:           logs,
				Traffic:        r.traffic,
				ProfileTraffic: r.profileTraffic,
				peers:          r.peers,
			}).Start(ctx)
			if ctx.Err() != nil {
				break
			}
			if logs != nil {
				logs.Add("ERROR", "transport stopped: %v; retrying in %s", err, backoff)
			}
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
			case <-timer.C:
			}
			if ctx.Err() != nil {
				break
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
		}
		r.mu.Lock()
		if r.gen == gen {
			r.run = false
			r.cancel = nil
		}
		r.mu.Unlock()
	}()
	return nil
}

func (r *Runtime) Toggle(enabled bool) error {
	r.mu.Lock()
	cfg := *r.cfg
	r.mu.Unlock()
	cfg.Enabled = enabled
	if err := r.ApplyConfig(cfg); err != nil {
		return fmt.Errorf("apply qwdtt state: %w", err)
	}
	return r.reconcile()
}
