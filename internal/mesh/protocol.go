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
	config              *types.NodeConfig
	conn                *net.UDPConn
	handlers            map[string]types.MessageHandler
	peers               map[string]*types.Connection
	peersMux            sync.RWMutex
	stopChan            chan struct{}
	wg                  sync.WaitGroup
	keyExchangeCallback func(peerName, publicKey, publicIP, wireGuardIP string) error
}

// NewProtocol creates a new mesh protocol instance
func NewProtocol(config *types.NodeConfig) *Protocol {
	return &Protocol{
		config:   config,
		handlers: make(map[string]types.MessageHandler),
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
	p.RegisterHandler(types.MsgTypeKeyExchangeRequest, p.handleKeyExchangeRequest)
	p.RegisterHandler(types.MsgTypeKeyExchangeResponse, p.handleKeyExchangeResponse)
	p.RegisterHandler(types.MsgTypeHeartbeat, p.handleHeartbeat)
	p.RegisterHandler(types.MsgTypePeerUpdate, p.handlePeerUpdate)
	p.RegisterHandler(types.MsgTypeSTUNRequest, p.handleSTUNRequest)
	p.RegisterHandler(types.MsgTypeSTUNResponse, p.handleSTUNResponse)

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
func (p *Protocol) RegisterHandler(msgType string, handler types.MessageHandler) {
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

// SetKeyExchangeCallback sets the callback function for handling key exchange requests
func (p *Protocol) SetKeyExchangeCallback(callback func(peerName, publicKey, publicIP, wireGuardIP string) error) {
	p.keyExchangeCallback = callback
}

func (p *Protocol) handleKeyExchangeRequest(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// Extract peer information from the request
	peerName, ok := msg.Data["name"].(string)
	if !ok {
		return fmt.Errorf("invalid peer name in key exchange request")
	}

	publicKey, ok := msg.Data["public_key"].(string)
	if !ok {
		return fmt.Errorf("invalid public key in key exchange request")
	}

	wireGuardIP, ok := msg.Data["wireguard_ip"].(string)
	if !ok {
		return fmt.Errorf("invalid wireguard IP in key exchange request")
	}

	publicIP := addr.IP.String()

	fmt.Printf("Received key exchange request from %s (%s)\n", peerName, publicIP)

	// Call the callback to add the peer to the configuration
	if p.keyExchangeCallback != nil {
		if err := p.keyExchangeCallback(peerName, publicKey, publicIP, wireGuardIP); err != nil {
			fmt.Printf("Failed to add peer %s: %v\n", peerName, err)
			return err
		}
	}

	// Send response with our public key back to the sender's address
	responseData := map[string]interface{}{
		"name":         p.config.Name,
		"public_key":   p.config.PublicKey,
		"wireguard_ip": p.config.WireGuardIP,
		"success":      true,
	}

	response := &types.MeshMessage{
		Type:      types.MsgTypeKeyExchangeResponse,
		From:      p.config.Name,
		To:        peerName,
		Timestamp: time.Now(),
		Data:      responseData,
	}

	// Send response back to the address that sent the request
	data, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	if _, err := p.conn.WriteToUDP(data, addr); err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}

	return nil
}

func (p *Protocol) handleKeyExchangeResponse(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// This is handled by the CLI command waiting for the response
	// The response will be picked up by SendKeyExchangeRequest
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

// SendKeyExchangeRequest sends a key exchange request and waits for a response
func (p *Protocol) SendKeyExchangeRequest(peerName, publicIP, wireGuardIP string, timeout time.Duration) (string, error) {
	// Create a channel to receive the response
	responseChan := make(chan *types.MeshMessage, 1)

	// Register a temporary handler for the response
	responseHandler := func(msg *types.MeshMessage, addr *net.UDPAddr) error {
		if msg.From == peerName && msg.Type == types.MsgTypeKeyExchangeResponse {
			responseChan <- msg
		}
		return nil
	}

	// Register the handler
	p.RegisterHandler(types.MsgTypeKeyExchangeResponse, responseHandler)
	defer func() {
		// Restore the default handler
		p.RegisterHandler(types.MsgTypeKeyExchangeResponse, p.handleKeyExchangeResponse)
	}()

	// Send the key exchange request
	requestData := map[string]interface{}{
		"name":         p.config.Name,
		"public_key":   p.config.PublicKey,
		"wireguard_ip": p.config.WireGuardIP,
	}

	// Send directly to IP since peer might not be in config yet
	msg := &types.MeshMessage{
		Type:      types.MsgTypeKeyExchangeRequest,
		From:      p.config.Name,
		To:        peerName,
		Timestamp: time.Now(),
		Data:      requestData,
	}
	if err := p.sendMessageToAddr(msg, publicIP, p.config.MeshPort); err != nil {
		return "", fmt.Errorf("failed to send key exchange request: %w", err)
	}

	// Wait for response with timeout
	select {
	case response := <-responseChan:
		publicKey, ok := response.Data["public_key"].(string)
		if !ok {
			return "", fmt.Errorf("invalid public key in response")
		}
		return publicKey, nil
	case <-time.After(timeout):
		return "", fmt.Errorf("timeout waiting for key exchange response")
	}
}

// GetConn returns the UDP connection for use by other components
func (p *Protocol) GetConn() *net.UDPConn {
	return p.conn
}

// STUN-related handlers (to be implemented by STUN server)
func (p *Protocol) handleSTUNRequest(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// This will be handled by registering the STUN server's handler
	return nil
}

func (p *Protocol) handleSTUNResponse(msg *types.MeshMessage, addr *net.UDPAddr) error {
	// This will be handled by registering the STUN server's handler
	return nil
}
