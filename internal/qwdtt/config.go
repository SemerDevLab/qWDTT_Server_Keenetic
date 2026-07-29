package qwdtt

import (
	"fmt"
	"net"
	"strings"
)

// Mode selects the role of the router in the WDTT network.
type Mode string

const ModeServer Mode = "server"

// RouteMode controls which LAN traffic is sent through the tunnel.
type RouteMode string

const (
	RouteAll       RouteMode = "all"
	RouteSelective RouteMode = "selective"
	RouteInternet  RouteMode = "internet"
)

// Config is the router-facing qWDTT configuration. It intentionally contains
// no Keenetic-specific API details; those belong to the routing backend.
type Config struct {
	Enabled   bool   `json:"enabled"`
	Mode      Mode   `json:"mode"`
	DataDir   string `json:"dataDir"`
	WebListen string `json:"webListen"`
	// WebAuth is a pointer so configurations created before this setting was
	// introduced keep the existing secure default (authorization enabled).
	WebAuth *bool `json:"webAuth,omitempty"`

	Client   ClientConfig   `json:"client"`
	Server   ServerConfig   `json:"server"`
	Routing  RoutingConfig  `json:"routing"`
	Firewall FirewallConfig `json:"firewall"`
}

func (c Config) WebAuthEnabled() bool {
	return c.WebAuth == nil || *c.WebAuth
}

type ClientConfig struct {
	Peer       string   `json:"peer"`
	DTLSPort   int      `json:"dtlsPort"`
	WGPort     int      `json:"wgPort"`
	ListenPort int      `json:"listenPort"`
	Password   string   `json:"password"`
	VKHashes   []string `json:"vkHashes"`
	Workers    int      `json:"workers"`
}

type ServerConfig struct {
	PublicHost string              `json:"publicHost"`
	ListenAddr string              `json:"listenAddr"`
	WGPort     int                 `json:"wgPort"`
	VPNPort    int                 `json:"vpnPort"`
	DTLSPort   int                 `json:"dtlsPort"`
	Password   string              `json:"password"`
	Network    string              `json:"network"`
	VKHash     string              `json:"vkHash"`
	Profiles   []ConnectionProfile `json:"profiles"`
}

// ConnectionProfile represents one client identity. Each profile receives a
// fixed tunnel address and its own DTLS endpoint/client link.
type ConnectionProfile struct {
	ID         string         `json:"id"`
	Name       string         `json:"name"`
	Enabled    bool           `json:"enabled"`
	ClientIP   string         `json:"clientIP"`
	VKHash     string         `json:"vkHash"`
	VKHashes   []string       `json:"vkHashes,omitempty"`
	Workers    int            `json:"workers,omitempty"`
	DTLSPort   int            `json:"dtlsPort"`
	AccessMode RouteMode      `json:"accessMode"`
	Firewall   FirewallConfig `json:"firewall"`
}

type FirewallConfig struct {
	Rules       []FirewallRule `json:"rules,omitempty"`
	Addresses   []string       `json:"addresses"`
	AddressMode string         `json:"addressMode"`
	Ports       []string       `json:"ports"`
	PortMode    string         `json:"portMode"`
}

type FirewallRule struct {
	Action          string   `json:"action"`
	ID              string   `json:"id,omitempty"`
	Name            string   `json:"name,omitempty"`
	Enabled         *bool    `json:"enabled,omitempty"`
	Family          string   `json:"family,omitempty"`
	SourceAddresses []string `json:"sourceAddresses,omitempty"`
	Addresses       []string `json:"addresses,omitempty"`
	Ports           []string `json:"ports,omitempty"`
	Protocol        string   `json:"protocol,omitempty"`
}

type RoutingConfig struct {
	Mode      RouteMode `json:"mode"`
	Interface string    `json:"interface"`
	Clients   []string  `json:"clients"`
	Networks  []string  `json:"networks"`
	DNS       []string  `json:"dns"`
	WAN       string    `json:"wan"`
}

func (c Config) Validate() error {
	if c.Mode != ModeServer {
		return fmt.Errorf("mode must be %q", ModeServer)
	}
	if c.Routing.Mode != RouteAll && c.Routing.Mode != RouteInternet && c.Routing.Mode != RouteSelective {
		return fmt.Errorf("routing.mode must be %q, %q or %q", RouteAll, RouteInternet, RouteSelective)
	}
	if strings.TrimSpace(c.Server.Password) == "" {
		return fmt.Errorf("server.password is required")
	}
	if strings.TrimSpace(c.Server.PublicHost) == "" {
		return fmt.Errorf("server.publicHost is required")
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return fmt.Errorf("dataDir is required")
	}
	if strings.TrimSpace(c.Server.Network) == "" {
		return fmt.Errorf("server.network is required")
	}
	ip, network, err := net.ParseCIDR(c.Server.Network)
	if err != nil {
		return fmt.Errorf("invalid server.network: %w", err)
	}
	if ip.To4() == nil {
		return fmt.Errorf("server.network must be IPv4")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return fmt.Errorf("server.network must contain usable client addresses")
	}
	serverIP, _, err := serverTunnelAddress(c.Server.Network)
	if err != nil {
		return err
	}
	networkIP := network.IP.To4()
	broadcast := lastIPv4(network)
	ids := make(map[string]bool)
	ips := make(map[string]bool)
	for i, profile := range c.Server.Profiles {
		if strings.TrimSpace(profile.ID) == "" {
			return fmt.Errorf("server.profiles[%d].id is required", i)
		}
		if ids[profile.ID] {
			return fmt.Errorf("duplicate profile id %q", profile.ID)
		}
		ids[profile.ID] = true
		if profile.AccessMode != RouteAll && profile.AccessMode != RouteInternet {
			return fmt.Errorf("profile %q accessMode must be %q or %q", profile.Name, RouteAll, RouteInternet)
		}
		hashes := profileHashes(profile)
		if len(hashes) > 4 {
			return fmt.Errorf("profile %q supports at most 4 VK hashes", profile.Name)
		}
		if profile.Workers != 0 && (profile.Workers < 9 || profile.Workers%9 != 0 || (len(hashes) > 0 && profile.Workers > len(hashes)*27)) {
			return fmt.Errorf("profile %q workers must be a multiple of 9 and no more than 27 per VK hash", profile.Name)
		}
		if err := validateFirewall(profile.Firewall); err != nil {
			return fmt.Errorf("profile %q firewall: %w", profile.Name, err)
		}
		clientIP := net.ParseIP(strings.TrimSpace(profile.ClientIP)).To4()
		if clientIP == nil || !network.Contains(clientIP) || clientIP.Equal(networkIP) || clientIP.Equal(serverIP) || clientIP.Equal(broadcast) {
			return fmt.Errorf("profile %q has invalid clientIP %q", profile.Name, profile.ClientIP)
		}
		canonicalIP := clientIP.String()
		if ips[canonicalIP] {
			return fmt.Errorf("duplicate profile clientIP %q", canonicalIP)
		}
		ips[canonicalIP] = true
	}
	if err := validateFirewall(c.Firewall); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	if c.Routing.Mode == RouteSelective && len(c.Routing.Clients) == 0 && len(c.Routing.Networks) == 0 {
		return fmt.Errorf("selective routing requires clients or networks")
	}
	return nil
}

func validateFirewall(f FirewallConfig) error {
	if f.AddressMode != "" && f.AddressMode != "allow" && f.AddressMode != "block" {
		return fmt.Errorf("addressMode must be allow or block")
	}
	if f.PortMode != "" && f.PortMode != "allow" && f.PortMode != "block" {
		return fmt.Errorf("portMode must be allow or block")
	}
	for _, rule := range f.Rules {
		if rule.Action != "allow" && rule.Action != "block" {
			return fmt.Errorf("rule action must be allow or block")
		}
		if rule.Protocol != "" && rule.Protocol != "all" && rule.Protocol != "ipv4" && rule.Protocol != "tcp" && rule.Protocol != "udp" {
			return fmt.Errorf("rule protocol must be ipv4, tcp or udp")
		}
		if rule.Family != "" && rule.Family != "ipv4" {
			return fmt.Errorf("rule family must be ipv4")
		}
		if err := validateFirewallValues(append(rule.SourceAddresses, rule.Addresses...), rule.Ports); err != nil {
			return err
		}
	}
	return validateFirewallValues(f.Addresses, f.Ports)
}

func validateFirewallValues(addresses, ports []string) error {
	for _, value := range addresses {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if ip := net.ParseIP(value); ip == nil {
			if _, _, err := net.ParseCIDR(value); err != nil {
				return fmt.Errorf("invalid address %q", value)
			}
		}
	}
	for _, value := range ports {
		parts := strings.Split(strings.TrimSpace(value), "-")
		if len(parts) > 2 {
			return fmt.Errorf("invalid port %q", value)
		}
		from, to := 0, 0
		for index, part := range parts {
			var port int
			if _, err := fmt.Sscan(strings.TrimSpace(part), &port); err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("invalid port %q", value)
			}
			if index == 0 {
				from = port
			} else {
				to = port
			}
		}
		if to != 0 && from > to {
			return fmt.Errorf("invalid port range %q", value)
		}
	}
	return nil
}

// NormalizeProfiles migrates legacy single-profile configurations and fills
// fields that may be omitted by older control panels.
func (c *Config) NormalizeProfiles() {
	c.Server.VKHash = normalizeVKHash(c.Server.VKHash)
	if c.Server.Profiles == nil {
		port := c.Server.DTLSPort
		if port == 0 {
			port = 56000
		}
		clientIP := ""
		if serverIP, _, err := serverTunnelAddress(c.Server.Network); err == nil {
			clientIP = nextIPv4(serverIP).String()
		}
		c.Server.Profiles = []ConnectionProfile{{
			ID:       "default",
			Name:     "Основной",
			Enabled:  true,
			ClientIP: clientIP,
			VKHash:   c.Server.VKHash,
			DTLSPort: port,
			AccessMode: func() RouteMode {
				if c.Routing.Mode == RouteInternet {
					return RouteInternet
				}
				return RouteAll
			}(),
		}}
	}
	basePort := c.Server.DTLSPort
	if basePort == 0 {
		basePort = 56000
	}
	for i := range c.Server.Profiles {
		profile := &c.Server.Profiles[i]
		if strings.TrimSpace(profile.ID) == "" {
			profile.ID = fmt.Sprintf("profile-%d", i+1)
		}
		if strings.TrimSpace(profile.Name) == "" {
			profile.Name = fmt.Sprintf("Профиль %d", i+1)
		}
		profile.VKHash = normalizeVKHash(profile.VKHash)
		profile.VKHashes = normalizeVKHashes(profile.VKHashes, profile.VKHash)
		if len(profile.VKHashes) > 0 {
			profile.VKHash = profile.VKHashes[0]
		}
		if profile.Workers == 0 {
			profile.Workers = 9
		}
		if profile.AccessMode == "" {
			profile.AccessMode = RouteAll
		}
		profile.DTLSPort = basePort // retained in JSON for backward compatibility
		if profile.Firewall.AddressMode == "" {
			profile.Firewall.AddressMode = "allow"
		}
		if profile.Firewall.PortMode == "" {
			profile.Firewall.PortMode = "allow"
		}
	}
	if _, network, err := net.ParseCIDR(c.Server.Network); err == nil && network.IP.To4() != nil {
		serverIP, _, serverErr := serverTunnelAddress(c.Server.Network)
		if serverErr != nil {
			return
		}
		broadcast := lastIPv4(network)
		used := make(map[string]bool, len(c.Server.Profiles))
		for i := range c.Server.Profiles {
			current := net.ParseIP(strings.TrimSpace(c.Server.Profiles[i].ClientIP)).To4()
			if current == nil || !network.Contains(current) || current.Equal(serverIP) || current.Equal(broadcast) || used[current.String()] {
				c.Server.Profiles[i].ClientIP = ""
				continue
			}
			c.Server.Profiles[i].ClientIP = current.String()
			used[current.String()] = true
		}
		candidate := nextIPv4(serverIP)
		for i := range c.Server.Profiles {
			if c.Server.Profiles[i].ClientIP != "" {
				continue
			}
			for network.Contains(candidate) && (candidate.Equal(serverIP) || candidate.Equal(broadcast) || used[candidate.String()]) {
				candidate = nextIPv4(candidate)
			}
			if !network.Contains(candidate) || candidate.Equal(broadcast) {
				continue
			}
			value := candidate.String()
			c.Server.Profiles[i].ClientIP = value
			used[value] = true
			candidate = nextIPv4(candidate)
		}
	}
}
