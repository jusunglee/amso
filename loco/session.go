package loco

import (
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

const (
	// MaxPacketID is the upper bound before packet IDs wrap around.
	MaxPacketID = 100000
	// DefaultPingInterval is the default keepalive interval.
	DefaultPingInterval = 60 * time.Second
)

// PushHandler is called for unsolicited server-push packets (e.g. MSG, KICKOUT).
type PushHandler func(p *Packet)

// Session manages a LOCO protocol session over an encrypted connection.
// It handles packet ID sequencing, request/response matching, and keepalive pings.
type Session struct {
	conn *SecureConn

	packetID atomic.Uint32

	pending   map[uint32]chan *Packet
	pendingMu sync.Mutex

	OnPush PushHandler

	done     chan struct{}
	closeOnce sync.Once
}

// NewSession creates a Session over the given SecureConn and starts the read loop and ping loop.
func NewSession(conn *SecureConn) *Session {
	s := &Session{
		conn:    conn,
		pending: make(map[uint32]chan *Packet),
		done:    make(chan struct{}),
	}
	go s.readLoop()
	go s.pingLoop()
	return s
}

// nextID returns the next packet ID, wrapping at MaxPacketID.
func (s *Session) nextID() uint32 {
	for {
		old := s.packetID.Load()
		next := (old + 1) % MaxPacketID
		if next == 0 {
			next = 1
		}
		if s.packetID.CompareAndSwap(old, next) {
			return next
		}
	}
}

// Request sends a LOCO command and waits for the matching response.
func (s *Session) Request(method string, body bson.M) (*Packet, error) {
	return s.RequestTimeout(method, body, 30*time.Second)
}

// RequestTimeout sends a LOCO command and waits for the response with a custom timeout.
func (s *Session) RequestTimeout(method string, body bson.M, timeout time.Duration) (*Packet, error) {
	bodyBytes, err := bson.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("loco: marshal body: %w", err)
	}

	id := s.nextID()
	ch := make(chan *Packet, 1)

	s.pendingMu.Lock()
	s.pending[id] = ch
	s.pendingMu.Unlock()

	p := &Packet{
		ID:       id,
		Method:   method,
		DataType: DataTypeBSON,
		Body:     bson.Raw(bodyBytes),
	}

	if err := s.conn.SendPacket(p); err != nil {
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		s.pendingMu.Lock()
		delete(s.pending, id)
		s.pendingMu.Unlock()
		return nil, fmt.Errorf("loco: request %s (id=%d) timed out", method, id)
	case <-s.done:
		return nil, fmt.Errorf("loco: session closed")
	}
}

// Send sends a LOCO command without waiting for a response (fire-and-forget).
func (s *Session) Send(method string, body bson.M) error {
	bodyBytes, err := bson.Marshal(body)
	if err != nil {
		return fmt.Errorf("loco: marshal body: %w", err)
	}

	id := s.nextID()
	p := &Packet{
		ID:       id,
		Method:   method,
		DataType: DataTypeBSON,
		Body:     bson.Raw(bodyBytes),
	}

	return s.conn.SendPacket(p)
}

func (s *Session) readLoop() {
	for {
		select {
		case <-s.done:
			return
		default:
		}

		pkt, err := s.conn.RecvPacket()
		if err != nil {
			select {
			case <-s.done:
				return
			default:
				log.Printf("loco: read error: %v", err)
				s.Close()
				return
			}
		}

		s.pendingMu.Lock()
		ch, ok := s.pending[pkt.ID]
		if ok {
			delete(s.pending, pkt.ID)
		}
		s.pendingMu.Unlock()

		if ok {
			ch <- pkt
		} else if s.OnPush != nil {
			s.OnPush(pkt)
		}
	}
}

func (s *Session) pingLoop() {
	ticker := time.NewTicker(DefaultPingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.Send("PING", bson.M{}); err != nil {
				log.Printf("loco: ping error: %v", err)
				return
			}
		}
	}
}

// Close shuts down the session and underlying connection.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		err = s.conn.Close()

		s.pendingMu.Lock()
		for id, ch := range s.pending {
			close(ch)
			delete(s.pending, id)
		}
		s.pendingMu.Unlock()
	})
	return err
}
