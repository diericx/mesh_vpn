package commands

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/types"
)

// Add adds a new peer to the network
func Add(args []string) error {
	if len(args) < 3 {
		return fmt.Errorf("usage: mvpn add <name> <public-ip> <wireguard-ip>")
	}

	peerName := args[0]
	publicIP := args[1]
	wireGuardIP := args[2]

	// Load configuration
	configMgr := config.NewManager("")
	cfg, err := configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Check if peer already exists
	for _, p := range cfg.Peers {
		if p.Name == peerName {
			return fmt.Errorf("peer already exists: %s", peerName)
		}
	}

	fmt.Printf("Attempting automatic key exchange with %s...\n", peerName)

	// Try to perform automatic key exchange
	peerPublicKey, err := attemptKeyExchange(cfg, peerName, publicIP, wireGuardIP)
	if err != nil {
		fmt.Printf("Automatic key exchange failed: %v\n", err)
		fmt.Printf("Falling back to manual configuration...\n\n")
		peerPublicKey = "" // Will be added manually
	} else {
		fmt.Printf("✓ Key exchange successful!\n")
		fmt.Printf("✓ Received public key from %s\n\n", peerName)
	}

	// Create new peer with endpoint
	endpoint := fmt.Sprintf("%s:%d", publicIP, cfg.WireGuardPort)
	peer := types.Peer{
		Name:         peerName,
		PublicIP:     publicIP,
		WireGuardIP:  wireGuardIP,
		PublicKey:    peerPublicKey,
		Endpoint:     endpoint,
		LastSeen:     time.Now(),
		HasOpenPort:  false,                 // Will be determined through discovery
		AllowedIPs:   []string{wireGuardIP}, // Allow traffic from this peer's WireGuard IP
		PersistentKA: 25,                    // Default keepalive
	}

	// Add peer to configuration
	if err := config.AddPeer(cfg, peer); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	// Create default ACL rule (deny all)
	aclRule := types.ACLRule{
		PeerName: peerName,
		Incoming: false,
		Outgoing: false,
	}
	config.UpdateACLRule(cfg, aclRule)

	// Save configuration
	if err := configMgr.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Peer %s added successfully\n", peerName)
	fmt.Printf("Public IP: %s\n", publicIP)
	fmt.Printf("WireGuard IP: %s\n", wireGuardIP)

	if peerPublicKey != "" {
		fmt.Printf("Public Key: %s\n", peerPublicKey)
		fmt.Printf("\n✓ Peer has been automatically added to both nodes!\n")
		fmt.Printf("✓ %s should now see you in their peer list\n", peerName)
	} else {
		fmt.Printf("\nNote: You need to exchange public keys with this peer.\n")
		fmt.Printf("Your public key: %s\n", cfg.PublicKey)
		fmt.Printf("\nOnce you have the peer's public key, update the configuration manually:\n")
		fmt.Printf("  Edit /etc/mesh-vpn/config.json and add the peer's public_key\n")
	}

	fmt.Printf("\nTraffic is blocked by default. Use 'mvpn allow' to enable communication.\n")

	return nil
}

// attemptKeyExchange tries to perform automatic key exchange with the peer
func attemptKeyExchange(cfg *types.NodeConfig, peerName, publicIP, wireGuardIP string) (string, error) {
	// Create a temporary UDP connection on an ephemeral port
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0})
	if err != nil {
		return "", fmt.Errorf("failed to create UDP connection: %w", err)
	}
	defer conn.Close()

	// Create key exchange request message
	requestData := map[string]interface{}{
		"name":         cfg.Name,
		"public_key":   cfg.PublicKey,
		"wireguard_ip": cfg.WireGuardIP,
	}

	msg := &types.MeshMessage{
		Type:      types.MsgTypeKeyExchangeRequest,
		From:      cfg.Name,
		To:        peerName,
		Timestamp: time.Now(),
		Data:      requestData,
	}

	// Marshal the message
	data, err := json.Marshal(msg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal message: %w", err)
	}

	// Send to target peer
	targetAddr := &net.UDPAddr{
		IP:   net.ParseIP(publicIP),
		Port: cfg.MeshPort,
	}

	fmt.Printf("Sending key exchange request to %s (%s)...\n", peerName, publicIP)
	if _, err := conn.WriteToUDP(data, targetAddr); err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}

	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Wait for response
	buffer := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return "", fmt.Errorf("timeout waiting for response")
		}
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var response types.MeshMessage
	if err := json.Unmarshal(buffer[:n], &response); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Verify it's a key exchange response
	if response.Type != types.MsgTypeKeyExchangeResponse {
		return "", fmt.Errorf("unexpected response type: %s", response.Type)
	}

	// Extract public key
	publicKey, ok := response.Data["public_key"].(string)
	if !ok {
		return "", fmt.Errorf("invalid public key in response")
	}

	return publicKey, nil
}
