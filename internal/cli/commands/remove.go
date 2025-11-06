package commands

import (
	"fmt"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/wireguard"
)

// Remove removes a peer from the network
func Remove(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: mvpn remove <peer-name>")
	}

	peerName := args[0]

	// Load configuration
	configMgr := config.NewManager("")
	cfg, err := configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get peer before removing
	peer, err := config.GetPeer(cfg, peerName)
	if err != nil {
		return fmt.Errorf("peer not found: %s", peerName)
	}

	// Remove from WireGuard if interface exists
	wgMgr := wireguard.NewManager(cfg.InterfaceName)
	if wgMgr.InterfaceExists() && peer.PublicKey != "" {
		if err := wgMgr.RemovePeer(peer.PublicKey); err != nil {
			fmt.Printf("Warning: failed to remove peer from WireGuard: %v\n", err)
		}
	}

	// Remove ACL rule
	if err := config.RemoveACLRule(cfg, peerName); err != nil {
		fmt.Printf("Warning: failed to remove ACL rule: %v\n", err)
	}

	// Remove peer from configuration
	if err := config.RemovePeer(cfg, peerName); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}

	// Save configuration
	if err := configMgr.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Peer %s removed successfully\n", peerName)

	return nil
}
