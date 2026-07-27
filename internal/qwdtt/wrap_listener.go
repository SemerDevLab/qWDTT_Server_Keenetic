package qwdtt

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/transport/v4/udp"
)

// wrappedListener deliberately uses Pion's UDP listener. Its packet
// demultiplexer gives every remote UDP endpoint its own PacketConn, which is
// required for multiple qWDTT clients sharing one DTLS port.
type wrappedListener struct {
	inner    dtlsnet.PacketListener
	keys     []wrapIdentity
	logs     *LogBook
	close    sync.Once
	selected sync.Map
	conns    sync.Map
}

type wrapIdentity struct {
	id  string
	key []byte
}

type wrappedConn struct {
	inner      net.PacketConn
	keys       []wrapIdentity
	key        []byte
	profileID  string
	onSelected func(net.Addr, string)
	onClose    func(net.Addr)
	remote     net.Addr
	readBuf    []byte
	selected   bool
	mu         sync.Mutex
	state      *WrapState
	cfg        WrapConfig
	logs       *LogBook
	bad        uint32
	close      sync.Once
}

func newWrappedListener(addr *net.UDPAddr, keys []wrapIdentity, logs *LogBook) (*wrappedListener, error) {
	inner, err := udp.Listen("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("wrap UDP listen: %w", err)
	}
	return &wrappedListener{
		inner: dtlsnet.PacketListenerFromListener(inner),
		keys:  cloneWrapIdentities(keys),
		logs:  logs,
	}, nil
}

func cloneWrapIdentities(keys []wrapIdentity) []wrapIdentity {
	cloned := make([]wrapIdentity, len(keys))
	for i, identity := range keys {
		cloned[i] = wrapIdentity{id: identity.id, key: append([]byte(nil), identity.key...)}
	}
	return cloned
}

func (l *wrappedListener) Accept() (net.PacketConn, net.Addr, error) {
	pc, addr, err := l.inner.Accept()
	if err != nil {
		return nil, nil, err
	}
	var ssrcBytes [4]byte
	_, _ = rand.Read(ssrcBytes[:])
	ssrc := binary.BigEndian.Uint32(ssrcBytes[:])
	if ssrc == 0 {
		ssrc = 1
	}
	conn := &wrappedConn{
		inner:      pc,
		keys:       cloneWrapIdentities(l.keys),
		state:      NewWrapState(),
		cfg:        WrapConfig{SSRC: ssrc, PayloadType: 111, PaddingMax: 24},
		logs:       l.logs,
		onSelected: func(addr net.Addr, id string) { l.selected.Store(addr.String(), id) },
		remote:     addr,
	}
	l.conns.Store(addr.String(), conn)
	conn.onClose = func(addr net.Addr) {
		l.selected.Delete(addr.String())
		l.conns.Delete(addr.String())
	}
	return conn, addr, nil
}

func (l *wrappedListener) Close() error {
	var err error
	l.close.Do(func() { err = l.inner.Close() })
	return err
}

func (l *wrappedListener) Addr() net.Addr { return l.inner.Addr() }
func (l *wrappedListener) ProfileID(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	value, _ := l.selected.Load(addr.String())
	id, _ := value.(string)
	return id
}

func (c *wrappedConn) ReadFrom(p []byte) (int, net.Addr, error) {
	required := len(p) + 80
	if cap(c.readBuf) < required {
		c.readBuf = make([]byte, required)
	}
	buf := c.readBuf[:required]
	for {
		n, addr, err := c.inner.ReadFrom(buf)
		if err != nil {
			return 0, addr, err
		}
		if !c.selected {
			var (
				m         int
				selected  wrapIdentity
				unwrapErr error
			)
			for _, identity := range c.keys {
				m, unwrapErr = UnwrapPacket(identity.key, buf[:n], p)
				if unwrapErr == nil {
					selected = identity
					break
				}
			}
			if unwrapErr != nil {
				if atomic.AddUint32(&c.bad, 1) <= 5 {
					pt := -1
					if n > 1 {
						pt = int(buf[1] & 0x7f)
					}
					c.logs.Add("WARN", "[WRAP %s] inbound rejected: bytes=%d rtpVersion=%d payloadType=%d attempt=%d/5 error=%v", addr, n, buf[0]>>6, pt, atomic.LoadUint32(&c.bad), unwrapErr)
				}
				continue
			}
			c.mu.Lock()
			c.key = append([]byte(nil), selected.key...)
			c.profileID = selected.id
			c.selected = true
			if len(buf) > 1 && buf[1]&0x7f == 96 {
				c.cfg.PayloadType = 96
				c.cfg.PaddingMax = 60
			}
			c.mu.Unlock()
			if c.onSelected != nil {
				c.onSelected(addr, selected.id)
			}
			return m, addr, nil
		}
		m, err := UnwrapPacket(c.key, buf[:n], p)
		if err != nil {
			// Match the original server: retry all currently active WRAP keys.
			// This supports a password/profile update without retaining a
			// permanently poisoned endpoint.
			for _, identity := range c.keys {
				if candidateN, candidateErr := UnwrapPacket(identity.key, buf[:n], p); candidateErr == nil {
					c.mu.Lock()
					c.key = append(c.key[:0], identity.key...)
					c.profileID = identity.id
					c.state = NewWrapState()
					c.mu.Unlock()
					if c.onSelected != nil {
						c.onSelected(addr, identity.id)
					}
					c.logs.Add("INFO", "WRAP key updated for %s", addr)
					return candidateN, addr, nil
				}
			}
			return 0, addr, fmt.Errorf("WRAP unwrap: %w", err)
		}
		return m, addr, nil
	}
}

func (c *wrappedConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	selected := c.selected
	cfg := c.cfg
	c.mu.Unlock()
	if !selected {
		return 0, fmt.Errorf("WRAP key not selected")
	}
	w, err := WrapPacket(c.key, p, cfg, c.state)
	if err != nil {
		return 0, err
	}
	if _, err = c.inner.WriteTo(w, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wrappedConn) Close() error {
	var err error
	c.close.Do(func() {
		if c.onClose != nil && c.remote != nil {
			c.onClose(c.remote)
		}
		err = c.inner.Close()
	})
	return err
}
func (c *wrappedConn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *wrappedConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *wrappedConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *wrappedConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

var _ dtlsnet.PacketListener = (*wrappedListener)(nil)
