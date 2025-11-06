package mesh

import (
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/diericx/mesh-vpn/internal/types"
)

// Protocol handles mesh network communication
type Protocol struct {
	config   *types.NodeConfig
	conn     *net.UDPConn
	handlers map[string]MessageHandler
	peers    map[string]*types.Connection
	peersMux sync.RWMutex
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// MessageHandler is a function that handles incoming messages
type MessageHandler func(msg *types.MeshMessage, addr *net.UDPAddr) error

// NewProtocol creates a new mesh protocol instance
func NewProtocol(config *types.NodeConfig) *Protocol {
	return &Protocol{
		config:   config,
		handlers: make(map[string]MessageHandler),
		peers:    make(map[string]*types.Connection),
		stopChan: make(chan struct{}),
	}
}

// Start begins listening for mesh protocol messages
func (p *Protocol) Start() error {
	addr := &net.UDPAddr{
		Port: p.config.MeshPort,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start mesh protocol: %w", err)
	}

	p.conn = conn

	// Register default handlers
	p.RegisterHandler(types.MsgTypePeerAnnounce, p.handlePeerAnnounce)
	p.RegisterHandler(types.MsgTypeKeyExchange, p.handleKeyExchange)
	p.RegisterHandler(types.MsgTypeHeartbeat, p.handleHeartbeat)
	p.RegisterHandler(types.MsgTypePeerUpdate, p.handlePeerUpdate)

	// Start listening goroutine
	p.wg.Add(1)
	go p.listen()

	// Start heartbeat goroutine
	p.wg.Add(1)
	go p.sendHeartbeats()

	return nil
}

// Stop stops the mesh protocol
func (p *Protocol) Stop() error {
	close(p.stopChan)
	if p.conn != nil {
		p.conn.Close()
	}
	p.wg.Wait()
	return nil
}

// RegisterHandler registers a message handler for a specific message type
func (p *Protocol) RegisterHandler(msgType string, handler MessageHandler) {
	p.handlers[msgType] = handler
}

// SendMessage sends a message to a specific peer
func (p *Protocol) SendMessage(peerName string, msgType string, data map[string]interface{}) error {
	// Find peer
	var peer *types.Peer
	for i := range p.config.Peers {
		if p.config.Peers[i].Name == peerName {
			peer = &p.config.Peers[i]
			break
		}
	}

	if peer == nil {
		return fmt.Errorf("peer not found: %s", peerName)
	}

	if peer.PublicIP == "" {
		return fmt.Errorf("peer %s has no public IP", peerName)
	}

	msg := &types.MeshMessage{
		Type:      msgType,
		From:      p.config.Name,
		To:        peerName,
		Timestamp: time.Now(),
		Data:      data,
	}

	return p.sendMessageToAddr(msg, peer.PublicIP, p.config.MeshPort)
}

// BroadcastMessage sends a message to all known peers
func (p *Protocol) BroadcastMessage(msgType string, data map[string]interface{}) error {
	msg := &types.MeshMessage{
		Type:      msgType,
		From:      p.config.Name,
		Timestamp: time.Now(),
		Data:      data,
	}

	var lastErr error
	for _, peer := range p.config.Peers {
		if peer.PublicIP != "" {
			if err := p.sendMessageToAddr(msg, peer.PublicIP, p.config.MeshPort); err != nil {
				lastErr = err
			}
		}
	}

	return lastErr
}

// sendMessageToAddr sends a message to a specific address
func (p *Protocol) sendMessageToAddr(msg *types.MeshMessage, ip string, port int) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	addr := &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}

	if _, err := p.conn.WriteToUDP(data, addr); err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}

	return nil
}

// listen listens for incoming messages
func (p *Protocol) listen() {
	defer p.wg.Done()

	buffer := make([]byte, 65535)
	for {
		select {
		case <-p.stopChan:
			return
		default:
			p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := p.conn.ReadFromUDP(buffer)
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

			// Handle message
			if handler, ok := p.handlers[msg.Type]; ok {
				go handler(&msg, addr)
			}
		}
	}
}

// sendHeartbeats periodically sends heartbeat messages to all peers
func (p *Protocol) sendHeartbeats() {
	defer p.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopChan:
			return
		case <-ticker.C:
			data := map[string]interface{}{
				"timestamp": time.Now().Unix(),
			}
			p.BroadcastMessage(types.MsgTypeHeartbeat, data)
		}
	}
}

// Default message handlers

func (p *Protocol) handlePeerAnnounce(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// Handle peer announcement
	// This would update peer information in the config
	return nil
}

func (p *Protocol) handleKeyExchange(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// Handle key exchange
	// This would process WireGuard public key exchange
	return nil
}

func (p *Protocol) handleHeartbeat(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// Update last seen time for peer
	p.peersMux.Lock()
	defer p.peersMux.Unlock()

	if conn, ok := p.peers[msg.From]; ok {
		conn.LastHeartbeat = time.Now()
		conn.IsActive = true
	} else {
		p.peers[msg.From] = &types.Connection{
			PeerName:      msg.From,
			RemoteAddr:    addr,
			LastHeartbeat: time.Now(),
			IsActive:      true,
		}
	}

	return nil
}

func (p *Protocol) handlePeerUpdate(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// Handle peer update messages
	// This would update peer information when topology changes
	return nil
}

// GetActivePeers returns a list of currently active peers
func (p *Protocol) GetActivePeers() []string {
	p.peersMux.RLock()
	defer p.peersMux.RUnlock()

	var active []string
	cutoff := time.Now().Add(-2 * time.Minute)

	for name, conn := range p.peers {
		if conn.LastHeartbeat.After(cutoff) {
			active = append(active, name)
		}
	}

	return active
}

// AnnouncePresence announces this node's presence to the network
func (p *Protocol) AnnouncePresence() error {
	data := map[string]interface{}{
		"name":       p.config.Name,
		"public_key": p.config.PublicKey,
		"mesh_port":  p.config.MeshPort,
		"wg_port":    p.config.WireGuardPort,
	}

	return p.BroadcastMessage(types.MsgTypePeerAnnounce, data)
}
