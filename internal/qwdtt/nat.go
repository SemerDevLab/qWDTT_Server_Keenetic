package qwdtt

import (
	"context"
	"fmt"
)

func ApplyNAT(ctx context.Context, r CommandRunner, wan, network string) error {
	if r == nil {
		return fmt.Errorf("nat runner is nil")
	}
	if wan == "" {
		wan = "br0"
	}
	if network == "" {
		network = "10.66.0.0/16"
	}
	if e := r.Run(ctx, "sysctl", "-w", "net.ipv4.ip_forward=1"); e != nil {
		return e
	}
	return r.Run(ctx, "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", network, "-o", wan, "-j", "MASQUERADE")
}
func EnsureNAT(ctx context.Context, r CommandRunner, wan, network string) error {
	return EnsureNATMode(ctx, r, wan, network, false)
}

func EnsureDTLSWAN(ctx context.Context, r CommandRunner, wan string, port int) error {
	if r == nil {
		return fmt.Errorf("dtls firewall runner is nil")
	}
	if wan == "" {
		wan = "br0"
	}
	if port == 0 {
		port = 56000
	}
	args := []string{"-p", "udp", "--dport", fmt.Sprint(port), "-j", "ACCEPT"}
	redirect := []string{"-p", "udp", "--dport", fmt.Sprint(port), "-j", "REDIRECT", "--to-ports", fmt.Sprint(port)}
	// A REDIRECT from a UDP port to the same port is unnecessary for a socket
	// already bound to 0.0.0.0 and creates avoidable conntrack/NAT state on
	// Keenetic. Remove rules left by older qWDTT releases.
	_ = r.Run(ctx, "iptables", append([]string{"-t", "nat", "-D", "PREROUTING"}, redirect...)...)
	// An existing copy may sit below Keenetic's terminal reject after NDMS
	// rebuilds the chain. Reinsert it at the top on every service start.
	for range 16 {
		if err := r.Run(ctx, "iptables", append([]string{"-D", "INPUT"}, args...)...); err != nil {
			break
		}
	}
	return r.Run(ctx, "iptables", append([]string{"-I", "INPUT", "1"}, args...)...)
}

func RemoveDTLSWAN(ctx context.Context, r CommandRunner, wan string, port int) {
	if r == nil {
		return
	}
	if wan == "" {
		wan = "br0"
	}
	if port == 0 {
		port = 56000
	}
	args := []string{"-p", "udp", "--dport", fmt.Sprint(port), "-j", "ACCEPT"}
	redirect := []string{"-p", "udp", "--dport", fmt.Sprint(port), "-j", "REDIRECT", "--to-ports", fmt.Sprint(port)}
	_ = r.Run(ctx, "iptables", append([]string{"-t", "nat", "-D", "PREROUTING"}, redirect...)...)
	_ = r.Run(ctx, "iptables", append([]string{"-D", "INPUT"}, args...)...)
}

func EnsureNATMode(ctx context.Context, r CommandRunner, wan, network string, internetOnly bool) error {
	if wan == "" {
		wan = "br0"
	}
	if network == "" {
		network = "10.66.0.0/16"
	}
	if e := ApplyNAT(ctx, r, wan, network); e != nil {
		if e := r.Run(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network, "-o", wan, "-j", "MASQUERADE"); e != nil {
			return e
		}
	}
	// Do not depend solely on the configured interface here. On Keenetic the
	// LAN bridge is commonly configured as wan=br0, while the actual Internet
	// uplink may be ppp0 or another dynamically named interface. A source-only
	// rule keeps tunnel clients NATed on whichever interface owns the default
	// route, while remaining limited to the qWDTT network.
	if err := r.Run(ctx, "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", network, "-j", "MASQUERADE"); err != nil {
		if err := r.Run(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network, "-j", "MASQUERADE"); err != nil {
			return err
		}
	}
	// Keenetic commonly uses br0 for the LAN bridge and a different
	// interface for the Internet uplink.  Tunnel clients must be masqueraded
	// on the LAN bridge as well, otherwise replies from 192.168.1.0/24 (and
	// from the router itself) do not have a return route to the tunnel.
	if wan != "br0" {
		if err := r.Run(ctx, "iptables", "-t", "nat", "-C", "POSTROUTING", "-s", network, "-o", "br0", "-j", "MASQUERADE"); err != nil {
			if err := r.Run(ctx, "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network, "-o", "br0", "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}
	// The original server explicitly permits forwarding in both directions.
	// Without this, the tunnel can handshake while all routed traffic is
	// dropped by the router firewall.
	if err := r.Run(ctx, "iptables", "-C", "FORWARD", "-i", "wdtt0", "-j", "ACCEPT"); err != nil {
		_ = r.Run(ctx, "iptables", "-A", "FORWARD", "-i", "wdtt0", "-j", "ACCEPT")
	}
	if err := r.Run(ctx, "iptables", "-C", "FORWARD", "-o", "wdtt0", "-j", "ACCEPT"); err != nil {
		_ = r.Run(ctx, "iptables", "-A", "FORWARD", "-o", "wdtt0", "-j", "ACCEPT")
	}
	// Traffic addressed to the router itself (for example 192.168.1.1)
	// traverses INPUT rather than FORWARD and must be allowed separately.
	if err := r.Run(ctx, "iptables", "-C", "INPUT", "-i", "wdtt0", "-j", "ACCEPT"); err != nil {
		_ = r.Run(ctx, "iptables", "-A", "INPUT", "-i", "wdtt0", "-j", "ACCEPT")
	}
	privateNetworks := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	if internetOnly {
		// Internet-only mode must not expose the server LAN or the router's
		// private addresses through the tunnel. NAT remains enabled for WAN.
		for _, network := range privateNetworks {
			if err := r.Run(ctx, "iptables", "-C", "FORWARD", "-i", "wdtt0", "-d", network, "-j", "REJECT"); err != nil {
				if err := r.Run(ctx, "iptables", "-I", "FORWARD", "1", "-i", "wdtt0", "-d", network, "-j", "REJECT"); err != nil {
					return err
				}
			}
			if err := r.Run(ctx, "iptables", "-C", "INPUT", "-i", "wdtt0", "-d", network, "-j", "REJECT"); err != nil {
				if err := r.Run(ctx, "iptables", "-I", "INPUT", "1", "-i", "wdtt0", "-d", network, "-j", "REJECT"); err != nil {
					return err
				}
			}
		}
	} else {
		// Remove stale Internet-only blocks when switching back to full tunnel.
		for _, network := range privateNetworks {
			// Older releases could add the same direct rule more than once.
			// Delete several times so an upgrade cannot leave a hidden 10/8
			// rejection ahead of the new per-profile chain.
			for range 16 {
				_ = r.Run(ctx, "iptables", "-D", "FORWARD", "-i", "wdtt0", "-d", network, "-j", "REJECT")
				_ = r.Run(ctx, "iptables", "-D", "INPUT", "-i", "wdtt0", "-d", network, "-j", "REJECT")
			}
		}
	}
	return nil
}

// EnsureProfileAccessPolicies isolates Internet-only profiles by their fixed
// WireGuard source address while allowing other profiles to retain LAN access.
func EnsureProfileAccessPolicies(ctx context.Context, r CommandRunner, profiles []ConnectionProfile) error {
	return ensureProfilePolicies(ctx, r, profiles, FirewallConfig{})
}

func EnsureGlobalFirewallPolicies(ctx context.Context, r CommandRunner, profiles []ConnectionProfile, firewall FirewallConfig) error {
	return ensureProfilePolicies(ctx, r, profiles, firewall)
}

func ensureProfilePolicies(ctx context.Context, r CommandRunner, profiles []ConnectionProfile, global FirewallConfig) error {
	if r == nil {
		return fmt.Errorf("profile policy runner is nil")
	}
	const forwardChain = "QWDTT_PROFILE_FWD"
	const inputChain = "QWDTT_PROFILE_IN"
	for _, chain := range []string{forwardChain, inputChain} {
		_ = r.Run(ctx, "iptables", "-N", chain)
		if err := r.Run(ctx, "iptables", "-F", chain); err != nil {
			return err
		}
	}
	if err := r.Run(ctx, "iptables", "-C", "FORWARD", "-i", "wdtt0", "-j", forwardChain); err != nil {
		if err := r.Run(ctx, "iptables", "-I", "FORWARD", "1", "-i", "wdtt0", "-j", forwardChain); err != nil {
			return err
		}
	}
	if err := r.Run(ctx, "iptables", "-C", "INPUT", "-i", "wdtt0", "-j", inputChain); err != nil {
		if err := r.Run(ctx, "iptables", "-I", "INPUT", "1", "-i", "wdtt0", "-j", inputChain); err != nil {
			return err
		}
	}
	// Do not reject the entire 10.0.0.0/8 range here: qWDTT itself uses a
	// 10.x WireGuard network and Keenetic can pass routed packets through its
	// local stack. Blocking 10/8 can therefore cut off the tunnel itself.
	// The router/LAN range used by Keenetic is normally 192.168.0.0/16.
	privateNetworks := []string{"172.16.0.0/12", "192.168.0.0/16"}
	for _, profile := range profiles {
		if !profile.Enabled {
			continue
		}
		source := profile.ClientIP + "/32"
		if profile.AccessMode == RouteInternet {
			// Keenetic may transparently redirect public DNS (for example
			// 1.1.1.1:53) to its local DNS proxy before the filter chain sees the
			// packet. Permit only DNS to private destinations; all other access to
			// the router and LAN remains blocked below.
			for _, protocol := range []string{"udp", "tcp"} {
				if err := r.Run(ctx, "iptables", "-A", forwardChain, "-s", source, "-p", protocol, "--dport", "53", "-j", "ACCEPT"); err != nil {
					return err
				}
				if err := r.Run(ctx, "iptables", "-A", inputChain, "-s", source, "-p", protocol, "--dport", "53", "-j", "ACCEPT"); err != nil {
					return err
				}
			}
			for _, network := range privateNetworks {
				if err := r.Run(ctx, "iptables", "-A", forwardChain, "-s", source, "-d", network, "-j", "REJECT"); err != nil {
					return err
				}
				if err := r.Run(ctx, "iptables", "-A", inputChain, "-s", source, "-d", network, "-j", "REJECT"); err != nil {
					return err
				}
			}
		}
		firewall := profile.Firewall
		if len(global.Rules) > 0 || len(global.Addresses) > 0 || len(global.Ports) > 0 {
			firewall = global
		}
		if err := ensureProfileFirewall(ctx, r, forwardChain, inputChain, source, firewall); err != nil {
			return err
		}
	}
	if err := r.Run(ctx, "iptables", "-A", forwardChain, "-j", "RETURN"); err != nil {
		return err
	}
	return r.Run(ctx, "iptables", "-A", inputChain, "-j", "RETURN")
}

func ensureProfileFirewall(ctx context.Context, r CommandRunner, forwardChain, inputChain, source string, firewall FirewallConfig) error {
	rules := firewall.Rules
	if len(rules) == 0 && (len(firewall.Addresses) > 0 || len(firewall.Ports) > 0) {
		action := "allow"
		if firewall.AddressMode == "block" || firewall.PortMode == "block" {
			action = "block"
		}
		rules = []FirewallRule{{Action: action, Addresses: firewall.Addresses, Ports: firewall.Ports}}
	}
	if len(rules) == 0 {
		return nil
	}
	chains := []string{forwardChain, inputChain}
	add := func(chain string, args ...string) error {
		return r.Run(ctx, "iptables", append([]string{"-A", chain}, args...)...)
	}
	for _, chain := range chains {
		for _, rule := range rules {
			if rule.Enabled != nil && !*rule.Enabled {
				continue
			}
			target := "ACCEPT"
			if rule.Action == "block" {
				target = "REJECT"
			}
			addresses := rule.Addresses
			if len(addresses) == 0 {
				addresses = []string{""}
			}
			protocols := []string{""}
			if rule.Protocol == "tcp" || rule.Protocol == "udp" {
				protocols = []string{rule.Protocol}
			} else if len(rule.Ports) > 0 {
				protocols = []string{"tcp", "udp"}
			}
			ports := rule.Ports
			if len(ports) == 0 {
				ports = []string{""}
			}
			sources := rule.SourceAddresses
			if len(sources) == 0 {
				sources = []string{source}
			}
			for _, sourceAddress := range sources {
				for _, address := range addresses {
					for _, protocol := range protocols {
						for _, port := range ports {
							args := []string{"-s", sourceAddress}
							if address != "" {
								args = append(args, "-d", address)
							}
							if protocol != "" {
								args = append(args, "-p", protocol)
							}
							if port != "" {
								args = append(args, "--dport", port)
							}
							args = append(args, "-j", target)
							if err := add(chain, args...); err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}
	return nil
}
