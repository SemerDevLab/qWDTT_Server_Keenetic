package qwdtt

import (
	"sync"
	"testing"
	"time"
)

func TestProfileTrafficTracksSessionsAndBytes(t *testing.T) {
	t.Parallel()

	tracker := NewProfileTrafficTracker()
	traffic := tracker.Connect("phone")
	secondWorker := tracker.Connect("phone")
	traffic.AddRX(120)
	traffic.AddTX(80)

	snapshot := tracker.Snapshot()["phone"]
	if !snapshot.Connected || snapshot.Sessions != 2 || snapshot.RXBytes != 120 || snapshot.TXBytes != 80 || snapshot.LastSeen == nil {
		t.Fatalf("unexpected connected snapshot: %#v", snapshot)
	}

	tracker.Disconnect(traffic)
	snapshot = tracker.Snapshot()["phone"]
	if !snapshot.Connected || snapshot.Sessions != 1 {
		t.Fatalf("disconnecting one worker closed the profile: %#v", snapshot)
	}
	tracker.Disconnect(secondWorker)
	snapshot = tracker.Snapshot()["phone"]
	if snapshot.Connected || snapshot.Sessions != 0 {
		t.Fatalf("unexpected disconnected snapshot: %#v", snapshot)
	}
}

func TestProfileTrafficDoesNotReportStaleSessionAsConnected(t *testing.T) {
	t.Parallel()

	tracker := NewProfileTrafficTracker()
	traffic := tracker.Connect("phone")
	traffic.lastSeen.Store(time.Now().Add(-profileOnlineWindow - time.Second).UnixNano())
	traffic.AddTX(128)

	snapshot := tracker.Snapshot()["phone"]
	if snapshot.Connected {
		t.Fatalf("outgoing WireGuard traffic kept a stale TURN session online: %#v", snapshot)
	}
	if snapshot.Sessions != 0 {
		t.Fatalf("stale session was included in active count: %#v", snapshot)
	}

	traffic.Touch()
	if snapshot = tracker.Snapshot()["phone"]; !snapshot.Connected {
		t.Fatalf("fresh keepalive did not restore online status: %#v", snapshot)
	}
}

func TestProfileTrafficReconnectDoesNotAccumulateStaleSessions(t *testing.T) {
	t.Parallel()

	tracker := NewProfileTrafficTracker()
	for range 16 {
		session := tracker.Connect("phone")
		session.lastSeen.Store(time.Now().Add(-profileOnlineWindow - time.Second).UnixNano())
	}
	for range 16 {
		tracker.Connect("phone")
	}

	snapshot := tracker.Snapshot()["phone"]
	if !snapshot.Connected || snapshot.Sessions != 16 {
		t.Fatalf("reconnect accumulated stale sessions: %#v", snapshot)
	}
}

func TestProfileTrafficConcurrentAccounting(t *testing.T) {
	t.Parallel()

	tracker := NewProfileTrafficTracker()
	traffic := tracker.Connect("laptop")
	const workers = 32
	const packets = 200
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range packets {
				traffic.AddRX(10)
				traffic.AddTX(20)
			}
		}()
	}
	wg.Wait()
	tracker.Disconnect(traffic)

	snapshot := tracker.Snapshot()["laptop"]
	if snapshot.RXBytes != workers*packets*10 || snapshot.TXBytes != workers*packets*20 {
		t.Fatalf("lost concurrent traffic updates: %#v", snapshot)
	}
}
