package qwdtt

import (
	"fmt"
	"sync"
	"testing"
)

func TestPeerForConcurrentAllocation(t *testing.T) {
	t.Parallel()

	const clients = 32
	svc := Service{
		Config: Config{Server: ServerConfig{Network: "10.66.66.0/24"}},
		peers: &peerStore{
			peers: make(map[string]clientPeer),
		},
	}

	results := make(chan clientPeer, clients)
	errs := make(chan error, clients)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			peer, err := svc.peerFor(fmt.Sprintf("device-%d", id))
			if err != nil {
				errs <- err
				return
			}
			results <- peer
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatal(err)
	}
	ips := make(map[string]struct{}, clients)
	for peer := range results {
		if _, exists := ips[peer.ip]; exists {
			t.Fatalf("duplicate peer IP allocated: %s", peer.ip)
		}
		ips[peer.ip] = struct{}{}
	}
	if len(ips) != clients {
		t.Fatalf("allocated %d unique peers, want %d", len(ips), clients)
	}
}

func TestPeerForReusesDeviceIdentity(t *testing.T) {
	t.Parallel()

	svc := Service{
		Config: Config{Server: ServerConfig{Network: "10.66.66.0/24"}},
		peers: &peerStore{
			peers: make(map[string]clientPeer),
		},
	}
	first, err := svc.peerFor("same-device")
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.peerFor("same-device")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatal("same device received different peer configuration")
	}
}

func TestServerTunnelAddressFollowsConfiguredNetwork(t *testing.T) {
	t.Parallel()

	ip, prefix, err := serverTunnelAddress("10.77.8.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := ip.String(); got != "10.77.8.1" || prefix != 24 {
		t.Fatalf("unexpected tunnel address %s/%d", got, prefix)
	}
}
