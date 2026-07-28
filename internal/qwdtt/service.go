package qwdtt

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"
)

const (
	// A UDP endpoint is owned by one Pion DTLS connection until that connection
	// is closed. Keeping a vanished client around for many minutes makes a new
	// ClientHello from the same NAT mapping land in the stale connection instead
	// of Accept. The official client sends a keepalive every 25 seconds, so 90
	// seconds tolerates several missed keepalives while releasing dead endpoints
	// quickly enough for reconnects to recover without restarting the server.
	dtlsIdleTimeout        = 90 * time.Second
	connectionSetupTimeout = 90 * time.Second
	readyPacketTimeout     = 90 * time.Second
)

type Service struct {
	Config         Config
	Routing        Backend
	Logs           *LogBook
	WG             WGBackend
	WGPtr          *WGBackend
	Traffic        *TrafficStats
	ProfileTraffic *ProfileTrafficTracker
	peers          *peerStore
}

type clientPeer struct {
	ip   string
	pub  string
	priv string
}

type peerStore struct {
	mu    sync.Mutex
	peers map[string]clientPeer
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = filepath.Dir(path)
	}
	cfg.NormalizeProfiles()
	if err = cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (s Service) Start(ctx context.Context) error {
	if s.Logs == nil {
		s.Logs = NewLogBook()
	}
	if err := s.Config.Validate(); err != nil {
		return err
	}
	if s.peers == nil {
		s.peers = &peerStore{peers: make(map[string]clientPeer)}
	}
	if !s.Config.Enabled {
		return fmt.Errorf("qwdtt is disabled")
	}
	return s.startServer(ctx)
}

func (s Service) startClient(ctx context.Context) error {
	// The transport/TUN adapter is deliberately injected next. Returning a
	// descriptive error prevents a package from claiming the route prematurely.
	return fmt.Errorf("client transport backend is not configured")
}

func (s Service) startServer(ctx context.Context) error {
	priv, pub, keyErr := ensureKeyPair(s.Config.DataDir)
	if keyErr != nil {
		return fmt.Errorf("wireguard keys: %w", keyErr)
	}
	wg := s.WG
	if wg.Runner == nil {
		wg.Runner = OSRunner{}
	}
	wg.Interface = "wdtt0"
	wg.ServerPrivate = filepath.Join(s.Config.DataDir, "server.key")
	wg.ServerPublic = pub
	wg.ListenPort = s.Config.Server.WGPort
	if wg.ListenPort == 0 {
		wg.ListenPort = 56001
	}
	serverIP, prefix, err := serverTunnelAddress(s.Config.Server.Network)
	if err != nil {
		return err
	}
	wg.Address = fmt.Sprintf("%s/%d", serverIP, prefix)
	s.WGPtr = &wg
	if err := wg.Setup(ctx); err != nil {
		return fmt.Errorf("WireGuard setup failed: %w", err)
	} else {
		s.Logs.Add("INFO", "WireGuard interface %s started", wg.Interface)
		if restored, restoreErr := s.restoreWireGuardPeers(ctx); restoreErr != nil {
			return fmt.Errorf("restore WireGuard peers: %w", restoreErr)
		} else if restored > 0 {
			s.Logs.Add("INFO", "restored %d WireGuard peers after transport restart", restored)
		}
		if e := EnsureNATMode(ctx, wg.Runner, s.Config.Routing.WAN, s.Config.Server.Network, false); e != nil {
			s.Logs.Add("ERROR", "NAT setup failed: %v", e)
		} else {
			s.Logs.Add("INFO", "NAT enabled for %s", s.Config.Server.Network)
		}
		if e := EnsureGlobalFirewallPolicies(ctx, wg.Runner, s.Config.Server.Profiles, s.Config.Firewall); e != nil {
			return fmt.Errorf("profile access policies failed: %w", e)
		}
		if e := ApplyPolicy(ctx, wg.Runner, s.Config.Routing); e != nil {
			s.Logs.Add("ERROR", "policy routing failed: %v", e)
		} else if s.Config.Routing.Mode == RouteSelective {
			s.Logs.Add("INFO", "selective policy routing enabled")
		}
	}
	_ = priv
	enabled := make([]ConnectionProfile, 0, len(s.Config.Server.Profiles))
	for _, profile := range s.Config.Server.Profiles {
		if !profile.Enabled {
			continue
		}
		enabled = append(enabled, profile)
	}
	if len(enabled) == 0 {
		s.Logs.Add("WARN", "server is running without enabled connection profiles")
		<-ctx.Done()
		return nil
	}
	port := s.Config.Server.DTLSPort
	if port == 0 {
		port = 56000
	}
	if e := EnsureDTLSWAN(ctx, wg.Runner, s.Config.Routing.WAN, port); e != nil {
		s.Logs.Add("ERROR", "DTLS firewall rule failed: %v", e)
	} else {
		s.Logs.Add("INFO", "DTLS firewall ready: UDP %d is first in INPUT; enabled profiles=%d", port, len(enabled))
	}
	return s.serveProfiles(ctx, enabled)
}

func (s Service) restoreWireGuardPeers(ctx context.Context) (int, error) {
	if s.peers == nil || s.WGPtr == nil {
		return 0, nil
	}
	s.peers.mu.Lock()
	peers := make([]clientPeer, 0, len(s.peers.peers))
	for _, peer := range s.peers.peers {
		peers = append(peers, peer)
	}
	s.peers.mu.Unlock()
	for _, peer := range peers {
		if err := s.WGPtr.AddPeer(ctx, peer.pub, peer.ip); err != nil {
			return 0, err
		}
	}
	return len(peers), nil
}

func (s Service) serveProfiles(ctx context.Context, profiles []ConnectionProfile) error {
	host := "0.0.0.0"
	if configuredHost, _, err := net.SplitHostPort(s.Config.Server.ListenAddr); err == nil && configuredHost != "" {
		host = configuredHost
	}
	port := s.Config.Server.DTLSPort
	if port == 0 {
		port = 56000
	}
	addr := net.JoinHostPort(host, fmt.Sprint(port))
	dtlsProfiles := make([]DTLSProfile, 0, len(profiles))
	profilesByID := make(map[string]ConnectionProfile, len(profiles))
	for _, profile := range profiles {
		dtlsProfiles = append(dtlsProfiles, DTLSProfile{ID: profile.ID, Password: s.Config.profilePassword(profile)})
		profilesByID[profile.ID] = profile
	}
	var listener *profileListener
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		listener, err = ListenProfileDTLS(DTLSConfig{Address: addr, Password: s.Config.Server.Password, Identity: "qwdtt-server", Server: true, Logs: s.Logs}, dtlsProfiles)
		if err == nil {
			break
		}
		if ctx.Err() != nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("listen DTLS %s: %w", addr, err)
	}
	defer listener.Close()
	log.Printf("qWDTT server listening for %d profiles on %s", len(profiles), addr)
	s.Logs.Add("INFO", "shared DTLS listener started on %s", addr)
	go func() { <-ctx.Done(); _ = listener.Close() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.Logs.Add("WARN", "DTLS accept/handshake rejected: %v", err)
				continue
			}
		}
		go s.handleConnection(ctx, conn, profilesByID, listener.ProfileID)
	}
}

func (s Service) handleConnection(ctx context.Context, conn net.Conn, profiles map[string]ConnectionProfile, resolveProfile func(net.Addr) string) {
	started := time.Now()
	remote := conn.RemoteAddr().String()
	phase := "accepted"
	defer conn.Close()
	defer func() {
		s.Logs.Add("INFO", "[DTLS %s] stream closed at phase=%s after %s", remote, phase, time.Since(started).Round(time.Millisecond))
	}()
	stopOnShutdown := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopOnShutdown()
	s.Logs.Add("INFO", "[DTLS %s] transport accepted; handshake starting", remote)
	if dc, ok := conn.(*dtls.Conn); ok {
		phase = "handshake"
		handshakeStarted := time.Now()
		hctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
		if err := dc.HandshakeContext(hctx); err != nil {
			s.Logs.Add("ERROR", "[DTLS %s] handshake failed after %s: %v", remote, time.Since(handshakeStarted).Round(time.Millisecond), err)
			return
		}
		s.Logs.Add("INFO", "[DTLS %s] handshake completed in %s", remote, time.Since(handshakeStarted).Round(time.Millisecond))
	}
	phase = "profile-selection"
	profileID := resolveProfile(conn.RemoteAddr())
	profile, ok := profiles[profileID]
	if !ok {
		s.Logs.Add("WARN", "[DTLS %s] no enabled profile selected (resolved id=%q)", remote, profileID)
		return
	}
	s.Logs.Add("INFO", "[DTLS %s] selected profile=%q id=%s", remote, profile.Name, profile.ID)
	profileTraffic := s.ProfileTraffic.Connect(profile.ID)
	defer s.ProfileTraffic.Disconnect(profileTraffic)
	phase = "initial-command"
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		if err != io.EOF {
			s.Logs.Add("ERROR", "[DTLS %s profile=%s] initial command read failed: %v", remote, profile.ID, err)
		}
		return
	}
	command := string(buf[:n])
	s.Logs.Add("INFO", "[DTLS %s profile=%s] received command=%s bytes=%d", remote, profile.ID, commandKind(command), n)
	if strings.HasPrefix(command, "GETCONF:") {
		phase = "getconf"
		parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(command, "GETCONF:")), "|")
		password := ""
		if len(parts) > 2 {
			password = parts[2]
		}
		if password != s.Config.profilePassword(profile) {
			_, _ = conn.Write([]byte("DENIED:wrong_password"))
			s.Logs.Add("WARN", "[DTLS %s profile=%s] GETCONF rejected: wrong password", remote, profile.ID)
			return
		}
		deviceID := "unknown"
		if len(parts) > 1 && parts[1] != "" {
			deviceID = parts[1]
		}
		serverPublic := ""
		if s.WGPtr != nil {
			serverPublic = s.WGPtr.ServerPublic
		}
		if serverPublic == "" || s.WGPtr == nil {
			_, _ = conn.Write([]byte("NOCONF"))
			return
		}
		port := "9000"
		if s.Config.Server.VPNPort > 0 {
			port = fmt.Sprint(s.Config.Server.VPNPort)
		}
		if len(parts) > 0 && parts[0] != "" {
			port = parts[0]
		}
		peer, err := s.peerForProfile(profile, deviceID)
		if err != nil {
			_, _ = conn.Write([]byte("NOCONF"))
			return
		}
		if err := s.WGPtr.AddPeer(ctx, peer.pub, peer.ip); err != nil {
			s.Logs.Add("ERROR", "[DTLS %s profile=%s] adding WireGuard peer failed: %v", remote, profile.ID, err)
			_, _ = conn.Write([]byte("NOCONF"))
			return
		}
		_, _ = conn.Write([]byte(buildClientWGConfig(serverPublic, peer.priv, peer.ip, port, s.clientDNS())))
		_ = conn.SetReadDeadline(time.Now().Add(connectionSetupTimeout))
		n, err = conn.Read(buf)
		if err != nil {
			s.Logs.Add("INFO", "[DTLS %s profile=%s] setup ended while waiting after GETCONF: %v", remote, profile.ID, err)
			return
		}
		command = string(buf[:n])
		s.Logs.Add("INFO", "[DTLS %s profile=%s] command after GETCONF=%s bytes=%d", remote, profile.ID, commandKind(command), n)
	}
	if strings.HasPrefix(command, "AUTH:") {
		phase = "auth"
		_ = conn.SetReadDeadline(time.Now().Add(connectionSetupTimeout))
		n, err = conn.Read(buf)
		if err != nil {
			s.Logs.Add("INFO", "[DTLS %s profile=%s] setup ended while waiting after AUTH: %v", remote, profile.ID, err)
			return
		}
		command = string(buf[:n])
		s.Logs.Add("INFO", "[DTLS %s profile=%s] command after AUTH=%s bytes=%d", remote, profile.ID, commandKind(command), n)
	}
	if strings.TrimSpace(command) == "READY" {
		phase = "ready"
		_, _ = conn.Write([]byte("READY_OK"))
		_ = conn.SetReadDeadline(time.Now().Add(readyPacketTimeout))
		n, err = conn.Read(buf)
		if err != nil {
			s.Logs.Add("INFO", "[DTLS %s profile=%s] READY acknowledged but first WireGuard datagram was not received: %v", remote, profile.ID, err)
			return
		}
	}
	_ = conn.SetReadDeadline(time.Time{})
	phase = "wireguard-proxy"
	s.Logs.Add("INFO", "[DTLS %s profile=%s] WireGuard proxy started; first datagram=%d bytes", remote, profile.ID, n)
	if err := s.proxyWG(ctx, conn, buf[:n], profileTraffic); err != nil {
		s.Logs.Add("INFO", "[DTLS %s profile=%s] WireGuard proxy stopped: %v", remote, profile.ID, err)
	}
}

// clientDNS returns the DNS resolver reachable through the local router.
// Explicit routing.dns values remain supported; otherwise use the router's
// WireGuard address instead of sending client DNS requests to a public resolver.
func (s Service) clientDNS() string {
	for _, value := range s.Config.Routing.DNS {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	// Keenetic's DNS proxy normally listens on the LAN bridge address, not on
	// the service-owned WireGuard address. Prefer that local address so clients
	// can actually reach the router resolver through the tunnel.
	for _, interfaceName := range []string{"br0", s.Config.Routing.WAN} {
		if interfaceName = strings.TrimSpace(interfaceName); interfaceName == "" {
			continue
		}
		iface, err := net.InterfaceByName(interfaceName)
		if err != nil {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch value := addr.(type) {
			case *net.IPNet:
				ip = value.IP
			case *net.IPAddr:
				ip = value.IP
			}
			if ip = ip.To4(); ip != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}
	return "192.168.1.1"
}

func commandKind(command string) string {
	command = strings.TrimSpace(command)
	switch {
	case strings.HasPrefix(command, "GETCONF:"):
		return "GETCONF"
	case strings.HasPrefix(command, "AUTH:"):
		return "AUTH"
	case command == "READY":
		return "READY"
	case command == "":
		return "EMPTY"
	default:
		return "WIREGUARD"
	}
}

func (s Service) peerForProfile(profile ConnectionProfile, deviceID string) (clientPeer, error) {
	if s.peers == nil {
		s.peers = &peerStore{peers: make(map[string]clientPeer)}
	}
	s.peers.mu.Lock()
	defer s.peers.mu.Unlock()
	key := profile.ID
	if value, ok := s.peers.peers[key]; ok {
		return value, nil
	}
	clientIP := net.ParseIP(profile.ClientIP).To4()
	if clientIP == nil {
		return clientPeer{}, fmt.Errorf("profile %q has invalid client IP", profile.Name)
	}
	priv, pub, err := generateWGKeyPair()
	if err != nil {
		return clientPeer{}, err
	}
	peer := clientPeer{ip: clientIP.String(), pub: pub, priv: priv}
	s.peers.peers[key] = peer
	s.Logs.Add("INFO", "profile %s assigned %s to device %s", profile.Name, peer.ip, deviceID)
	return peer, nil
}

func (s Service) peerFor(deviceID string) (clientPeer, error) {
	if s.peers == nil {
		s.peers = &peerStore{peers: make(map[string]clientPeer)}
	}
	s.peers.mu.Lock()
	defer s.peers.mu.Unlock()
	if value, ok := s.peers.peers[deviceID]; ok {
		return value, nil
	}
	_, network, err := net.ParseCIDR(s.Config.Server.Network)
	if err != nil {
		return clientPeer{}, fmt.Errorf("invalid server.network: %w", err)
	}
	serverIP, _, err := serverTunnelAddress(s.Config.Server.Network)
	if err != nil {
		return clientPeer{}, err
	}
	broadcast := lastIPv4(network)
	for ip := nextIPv4(network.IP.Mask(network.Mask)); network.Contains(ip); ip = nextIPv4(ip) {
		if ip.Equal(serverIP) || ip.Equal(broadcast) || ip.IsUnspecified() {
			continue
		}
		candidate := ip.String()
		used := false
		for _, peer := range s.peers.peers {
			if peer.ip == candidate {
				used = true
				break
			}
		}
		if used {
			continue
		}
		// The private key is generated for the client configuration below; keep
		// it in the map so repeated GETCONF requests get the same peer.
		priv, pub, err := generateWGKeyPair()
		if err != nil {
			return clientPeer{}, err
		}
		p := clientPeer{ip: candidate, pub: pub, priv: priv}
		s.peers.peers[deviceID] = p
		return p, nil
	}
	return clientPeer{}, fmt.Errorf("server.network has no free client address")
}

func serverTunnelAddress(rawNetwork string) (net.IP, int, error) {
	ip, network, err := net.ParseCIDR(rawNetwork)
	if err != nil || ip.To4() == nil {
		return nil, 0, fmt.Errorf("invalid IPv4 server.network %q", rawNetwork)
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return nil, 0, fmt.Errorf("server.network has no usable client addresses")
	}
	return nextIPv4(network.IP.Mask(network.Mask)), ones, nil
}

func lastIPv4(network *net.IPNet) net.IP {
	ip := append(net.IP(nil), network.IP.To4()...)
	for i := range ip {
		ip[i] |= ^network.Mask[i]
	}
	return ip
}

func nextIPv4(ip net.IP) net.IP {
	n := append(net.IP(nil), ip.To4()...)
	for i := len(n) - 1; i >= 0; i-- {
		n[i]++
		if n[i] != 0 {
			break
		}
	}
	return n
}

func (s Service) proxyWG(ctx context.Context, conn net.Conn, first []byte, profileTraffic *ProfileSession) error {
	port := s.Config.Server.WGPort
	if port == 0 {
		port = 56001
	}
	wgConn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", port), 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect local WireGuard: %w", err)
	}
	defer wgConn.Close()
	if udpConn, ok := wgConn.(*net.UDPConn); ok {
		_ = udpConn.SetReadBuffer(2 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(2 * 1024 * 1024)
	}
	if _, err := wgConn.Write(first); err != nil {
		return err
	}
	proxyCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(proxyCtx, func() {
		_ = conn.SetDeadline(time.Now())
		_ = wgConn.SetDeadline(time.Now())
	})
	defer stop()
	var wg sync.WaitGroup
	copyLoop := func(dst interface{ Write([]byte) (int, error) }, src interface{ Read([]byte) (int, error) }, refreshReadDeadline func() error, add func(int)) {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			select {
			case <-proxyCtx.Done():
				return
			default:
			}
			if refreshReadDeadline != nil {
				if err := refreshReadDeadline(); err != nil {
					cancel()
					return
				}
			}
			n, err := src.Read(buf)
			if err != nil {
				cancel()
				return
			}
			if src == conn && n == 1 && buf[0] == 0xFF {
				// Official qWDTT keepalive: refresh the DTLS session without
				// forwarding the marker into the WireGuard UDP socket.
				profileTraffic.Touch()
				continue
			}
			if _, err = dst.Write(buf[:n]); err != nil {
				cancel()
				return
			}
			add(n)
		}
	}
	wg.Add(2)
	go copyLoop(conn, wgConn, nil, func(n int) {
		s.Traffic.AddTX(n)
		profileTraffic.AddTX(n)
	})
	go copyLoop(wgConn, conn, func() error {
		// Pion's UDP listener demultiplexes clients by remote IP:port.  A
		// vanished mobile client therefore has to be closed explicitly;
		// otherwise a later ClientHello from the same endpoint remains stuck
		// in the old DTLS connection and is never accepted as a new session.
		return conn.SetReadDeadline(time.Now().Add(dtlsIdleTimeout))
	}, func(n int) {
		s.Traffic.AddRX(n)
		profileTraffic.AddRX(n)
	})
	wg.Wait()
	return nil
}
