package commands

import (
	"fmt"
	"time"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/types"
)

// Add adds a new peer to the network
func Add(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: mvpn add <name> <public-ip>")
	}

	peerName := args[0]
	publicIP := args[1]

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

	// Create new peer
	peer := types.Peer{
		Name:         peerName,
		PublicIP:     publicIP,
		LastSeen:     time.Now(),
		HasOpenPort:  false, // Will be determined through discovery
		AllowedIPs:   []string{},
		PersistentKA: 25, // Default keepalive
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
	fmt.Printf("Note: Traffic is blocked by default. Use 'mvpn allow' to enable communication.\n")

	return nil
}
