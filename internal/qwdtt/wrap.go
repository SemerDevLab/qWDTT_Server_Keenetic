package qwdtt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type WrapConfig struct {
	SSRC        uint32
	PayloadType uint8
	PaddingMax  int
}
type WrapState struct {
	mu        sync.Mutex
	seq       uint16
	timestamp uint32
	last      time.Time
	count     uint64
}

func NewWrapState() *WrapState {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return &WrapState{seq: binary.BigEndian.Uint16(b[:2]), timestamp: binary.BigEndian.Uint32(b[2:])}
}

func buildNonce(ssrc uint32, seq uint16, ts uint32) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint32(n[:4], ssrc)
	binary.BigEndian.PutUint16(n[4:6], seq)
	binary.BigEndian.PutUint32(n[8:], ts)
	return n
}

func (s *WrapState) next() (uint16, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.count > 0 {
		d := uint32(now.Sub(s.last).Seconds() * 48000)
		if d < 120 {
			d = 120
		}
		if d > 2880 {
			d = 2880
		}
		s.timestamp += ((d + 60) / 120) * 120
	}
	seq, ts := s.seq, s.timestamp
	s.seq++
	s.last = now
	s.count++
	return seq, ts
}

func rtpTimestampStep(d time.Duration, jitter byte) uint32 {
	// The original wdtt-server advances an audio RTP clock in 2.5 ms
	// increments and adds a small deterministic-looking jitter component.
	samples := int64(d.Seconds() * 48000)
	if samples < 120 {
		samples = 120
	}
	if samples > 2880 {
		samples = 2880
	}
	samples = ((samples + 60) / 120) * 120
	samples += int64(int(jitter)%3-1) * 120
	if samples < 120 {
		samples = 120
	}
	if samples > 2880 {
		samples = 2880
	}
	return uint32(samples)
}

func WrapPacket(key, payload []byte, cfg WrapConfig, state *WrapState) ([]byte, error) {
	if len(key) != wrapKeyLen || len(payload) == 0 {
		return nil, errors.New("invalid key or empty payload")
	}
	if state == nil {
		state = NewWrapState()
	}
	var randomBytes [5]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return nil, err
	}
	state.mu.Lock()
	seq := state.seq
	if state.count > 0 {
		state.timestamp += rtpTimestampStep(time.Since(state.last), randomBytes[2])
	}
	ts := state.timestamp
	step := uint16(1)
	if randomBytes[4]&0x7f == 0 {
		step = 2 + uint16(randomBytes[4]>>7)
	}
	state.seq += step
	state.last = time.Now()
	state.count++
	state.mu.Unlock()
	nonce := buildNonce(cfg.SSRC, seq, ts)
	padding := 0
	if cfg.PaddingMax > 0 && randomBytes[0]&0x03 == 0 {
		padding = int(randomBytes[1])%cfg.PaddingMax + 1
	}
	out := make([]byte, 12+len(payload)+chacha20poly1305.Overhead+padding)
	out[0] = 0x80
	if padding > 0 {
		out[0] |= 0x20
	}
	out[1] = cfg.PayloadType & 0x7f
	if randomBytes[3]&0x3f == 0 {
		out[1] |= 0x80
	}
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint32(out[4:8], ts)
	binary.BigEndian.PutUint32(out[8:12], cfg.SSRC)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	sealed := aead.Seal(out[12:12], nonce, payload, out[:12])
	if padding > 0 {
		_, _ = rand.Read(out[12+len(sealed) : 12+len(sealed)+padding])
		out[len(out)-1] = byte(padding)
	}
	return out, nil
}

func UnwrapPacket(key, wire, dst []byte) (int, error) {
	if len(key) != wrapKeyLen || len(wire) < 13 || wire[0]>>6 != 2 {
		return 0, errors.New("invalid WRAP packet")
	}
	end := len(wire)
	if wire[0]&0x20 != 0 {
		p := int(wire[len(wire)-1])
		if p == 0 || p > end-12 {
			return 0, errors.New("invalid padding")
		}
		end -= p
	}
	if end-12 <= chacha20poly1305.Overhead {
		return 0, errors.New("no payload")
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return 0, err
	}
	plain, err := aead.Open(dst[:0], buildNonce(binary.BigEndian.Uint32(wire[8:12]), binary.BigEndian.Uint16(wire[2:4]), binary.BigEndian.Uint32(wire[4:8])), wire[12:end], wire[:12])
	if err != nil {
		return 0, fmt.Errorf("WRAP authentication failed: %w", err)
	}
	if len(plain) > len(dst) {
		return 0, errors.New("destination too small")
	}
	return len(plain), nil
}
