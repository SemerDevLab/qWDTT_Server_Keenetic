package qwdtt

import (
	"sync"
	"sync/atomic"
	"time"
)

type ProfileTrafficTracker struct {
	mu       sync.RWMutex
	profiles map[string]*ProfileTraffic
}

type ProfileTraffic struct {
	rx       atomic.Uint64
	tx       atomic.Uint64
	lastSeen atomic.Int64

	sessionsMu sync.RWMutex
	sessions   map[*ProfileSession]struct{}

	mu     sync.Mutex
	prevAt time.Time
	prevRX uint64
	prevTX uint64
}

type ProfileSession struct {
	traffic  *ProfileTraffic
	lastSeen atomic.Int64
}

type ProfileTrafficSnapshot struct {
	Connected bool       `json:"connected"`
	Sessions  int64      `json:"sessions"`
	RXBytes   uint64     `json:"rxBytes"`
	TXBytes   uint64     `json:"txBytes"`
	RXRate    float64    `json:"rxRate"`
	TXRate    float64    `json:"txRate"`
	LastSeen  *time.Time `json:"lastSeen,omitempty"`
}

// Official qWDTT clients send a DTLS keepalive every 15 seconds. TURN may
// swallow the close notification when a client disconnects, so the number of
// still-running server goroutines alone is not a reliable online indicator.
const profileOnlineWindow = 30 * time.Second

func NewProfileTrafficTracker() *ProfileTrafficTracker {
	return &ProfileTrafficTracker{profiles: make(map[string]*ProfileTraffic)}
}

func (t *ProfileTrafficTracker) Connect(profileID string) *ProfileSession {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	traffic := t.profiles[profileID]
	t.mu.RUnlock()
	if traffic == nil {
		t.mu.Lock()
		traffic = t.profiles[profileID]
		if traffic == nil {
			traffic = &ProfileTraffic{sessions: make(map[*ProfileSession]struct{})}
			t.profiles[profileID] = traffic
		}
		t.mu.Unlock()
	}
	session := &ProfileSession{traffic: traffic}
	session.touch()
	traffic.sessionsMu.Lock()
	traffic.sessions[session] = struct{}{}
	traffic.sessionsMu.Unlock()
	return session
}

func (t *ProfileTrafficTracker) Disconnect(session *ProfileSession) {
	if t == nil || session == nil || session.traffic == nil {
		return
	}
	session.traffic.sessionsMu.Lock()
	delete(session.traffic.sessions, session)
	session.traffic.sessionsMu.Unlock()
}

func (t *ProfileTrafficTracker) Snapshot() map[string]ProfileTrafficSnapshot {
	result := make(map[string]ProfileTrafficSnapshot)
	if t == nil {
		return result
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	for id, traffic := range t.profiles {
		result[id] = traffic.snapshot()
	}
	return result
}

func (s *ProfileSession) AddRX(n int) {
	if s != nil && s.traffic != nil && n > 0 {
		s.traffic.rx.Add(uint64(n))
		s.touch()
	}
}

func (s *ProfileSession) AddTX(n int) {
	if s != nil && s.traffic != nil && n > 0 {
		s.traffic.tx.Add(uint64(n))
	}
}

func (s *ProfileSession) Touch() {
	s.touch()
}

func (s *ProfileSession) touch() {
	if s != nil && s.traffic != nil {
		now := time.Now().UnixNano()
		s.lastSeen.Store(now)
		s.traffic.lastSeen.Store(now)
	}
}

func (t *ProfileTraffic) snapshot() ProfileTrafficSnapshot {
	now := time.Now()
	rx, tx := t.rx.Load(), t.tx.Load()
	lastSeenValue := t.lastSeen.Load()
	activeSessions := int64(0)
	t.sessionsMu.RLock()
	for session := range t.sessions {
		value := session.lastSeen.Load()
		if value > 0 && now.Sub(time.Unix(0, value)) <= profileOnlineWindow {
			activeSessions++
		}
	}
	t.sessionsMu.RUnlock()
	result := ProfileTrafficSnapshot{
		Connected: activeSessions > 0,
		Sessions:  activeSessions,
		RXBytes:   rx,
		TXBytes:   tx,
	}
	if lastSeenValue > 0 {
		lastSeen := time.Unix(0, lastSeenValue)
		result.LastSeen = &lastSeen
	}
	t.mu.Lock()
	if !t.prevAt.IsZero() {
		seconds := now.Sub(t.prevAt).Seconds()
		if seconds > 0 {
			result.RXRate = float64(rx-t.prevRX) / seconds
			result.TXRate = float64(tx-t.prevTX) / seconds
		}
	}
	t.prevAt, t.prevRX, t.prevTX = now, rx, tx
	t.mu.Unlock()
	return result
}
