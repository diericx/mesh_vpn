package stun

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/diericx/mesh-vpn/internal/types"
)

// Server provides STUN functionality for NAT traversal
type Server struct {
	config      *types.NodeConfig
	conn        *net.UDPConn
	sessions    map[string]*STUNSession
	sessionsMux sync.RWMutex
	stopChan    chan struct{}
	wg          sync.WaitGroup
}

// STUNSession represents an active STUN session
type STUNSession struct {
	RequesterName string
	TargetName    string
	RequesterAddr *net.UDPAddr
	TargetAddr    *net.UDPAddr
	CreatedAt     time.Time
	Completed     bool
}

// NewServer creates a new STUN server
func NewServer(config *types.NodeConfig) *Server {
	return &Server{
		config:   config,
		sessions: make(map[string]*STUNSession),
		stopChan: make(chan struct{}),
	}
}

// Start begins the STUN server
func (s *Server) Start() error {
	addr := &net.UDPAddr{
		Port: s.config.MeshPort,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start STUN server: %w", err)
	}

	s.conn = conn

	s.wg.Add(1)
	go s.listen()

	return nil
}

// Stop stops the STUN server
func (s *Server) Stop() error {
	close(s.stopChan)
	if s.conn != nil {
		s.conn.Close()
	}
	s.wg.Wait()
	return nil
}

// listen listens for STUN requests
func (s *Server) listen() {
	defer s.wg.Done()

	buffer := make([]byte, 65535)
	for {
		select {
		case <-s.stopChan:
			return
		default:
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			// Parse message
			var msg types.MeshMessage
			if err := json.Unmarshal(buffer[:n], &msg); err != nil {
				continue
			}

			// Handle STUN messages
			switch msg.Type {
			case types.MsgTypeSTUNRequest:
				go s.handleSTUNRequest(&msg, addr)
			}
		}
	}
}

// handleSTUNRequest processes a STUN request
func (s *Server) handleSTUNRequest(msg *types.MeshMessage, addr *net.UDPAddr) error {
	requesterName, ok := msg.Data["requester_name"].(string)
	if !ok {
		return fmt.Errorf("invalid requester_name")
	}

	targetName, ok := msg.Data["target_name"].(string)
	if !ok {
		return fmt.Errorf("invalid target_name")
	}

	sessionKey := fmt.Sprintf("%s-%s", requesterName, targetName)

	s.sessionsMux.Lock()
	session, exists := s.sessions[sessionKey]
	if !exists {
		session = &STUNSession{
			RequesterName: requesterName,
			TargetName:    targetName,
			CreatedAt:     time.Now(),
		}
		s.sessions[sessionKey] = session
	}

	// Store the address based on who sent the request
	if msg.From == requesterName {
		session.RequesterAddr = addr
	} else if msg.From == targetName {
		session.TargetAddr = addr
	}

	// If we have both addresses, send responses
	if session.RequesterAddr != nil && session.TargetAddr != nil && !session.Completed {
		session.Completed = true
		s.sessionsMux.Unlock()

		// Send target's endpoint to requester
		s.sendSTUNResponse(requesterName, targetName, session.TargetAddr, session.RequesterAddr)

		// Send requester's endpoint to target
		s.sendSTUNResponse(targetName, requesterName, session.RequesterAddr, session.TargetAddr)

		return nil
	}
	s.sessionsMux.Unlock()

	return nil
}

// sendSTUNResponse sends a STUN response with discovered endpoint
func (s *Server) sendSTUNResponse(to, from string, discoveredAddr, sendToAddr *net.UDPAddr) error {
	response := &types.MeshMessage{
		Type:      types.MsgTypeSTUNResponse,
		From:      s.config.Name,
		To:        to,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"target_name": from,
			"endpoint":    discoveredAddr.String(),
			"success":     true,
		},
	}

	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if _, err := s.conn.WriteToUDP(data, sendToAddr); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}

// CleanupSessions removes old sessions
func (s *Server) CleanupSessions() {
	s.sessionsMux.Lock()
	defer s.sessionsMux.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)
	for key, session := range s.sessions {
		if session.CreatedAt.Before(cutoff) {
			delete(s.sessions, key)
		}
	}
}

// Client provides STUN client functionality
type Client struct {
	config   *types.NodeConfig
	conn     *net.UDPConn
	response chan *types.STUNResponse
}

// NewClient creates a new STUN client
func NewClient(config *types.NodeConfig) *Client {
	return &Client{
		config:   config,
		response: make(chan *types.STUNResponse, 1),
	}
}

// RequestNATTraversal requests NAT traversal through a broker
func (c *Client) RequestNATTraversal(targetPeer, brokerPeer *types.Peer, timeout time.Duration) (*types.STUNResponse, error) {
	// Create UDP connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()
	c.conn = conn

	// Start listening for response
	done := make(chan struct{})
	go c.listenForResponse(done)

	// Send STUN request to broker
	request := &types.MeshMessage{
		Type:      types.MsgTypeSTUNRequest,
		From:      c.config.Name,
		To:        brokerPeer.Name,
		Timestamp: time.Now(),
		Data: map[string]interface{}{
			"requester_name": c.config.Name,
			"target_name":    targetPeer.Name,
			"broker_name":    brokerPeer.Name,
		},
	}

	brokerAddr := &net.UDPAddr{
		IP:   net.ParseIP(brokerPeer.PublicIP),
		Port: c.config.MeshPort,
	}

	data, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send request multiple times to ensure delivery
	for i := 0; i < 3; i++ {
		if _, err := c.conn.WriteToUDP(data, brokerAddr); err != nil {
			return nil, fmt.Errorf("failed to send STUN request: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Wait for response
	select {
	case resp := <-c.response:
		close(done)
		return resp, nil
	case <-time.After(timeout):
		close(done)
		return nil, fmt.Errorf("STUN request timeout")
	}
}

// listenForResponse listens for STUN responses
func (c *Client) listenForResponse(done chan struct{}) {
	buffer := make([]byte, 65535)
	for {
		select {
		case <-done:
			return
		default:
			c.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, _, err := c.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				continue
			}

			var msg types.MeshMessage
			if err := json.Unmarshal(buffer[:n], &msg); err != nil {
				continue
			}

			if msg.Type == types.MsgTypeSTUNResponse {
				endpoint, _ := msg.Data["endpoint"].(string)
				success, _ := msg.Data["success"].(bool)
				targetName, _ := msg.Data["target_name"].(string)

				resp := &types.STUNResponse{
					RequesterName: c.config.Name,
					TargetName:    targetName,
					Endpoint:      endpoint,
					Success:       success,
				}

				select {
				case c.response <- resp:
				default:
				}
				return
			}
		}
	}
}
