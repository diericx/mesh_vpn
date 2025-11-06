package commands

import (
	"fmt"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/firewall"
	"github.com/diericx/mesh-vpn/internal/types"
	"github.com/diericx/mesh-vpn/internal/wireguard"
)

// Allow allows traffic to/from a peer
func Allow(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: mvpn allow <incoming|outgoing> <peer-name>")
	}

	direction := args[0]
	peerName := args[1]

	if direction != "incoming" && direction != "outgoing" {
		return fmt.Errorf("direction must be 'incoming' or 'outgoing'")
	}

	// Load configuration
	configMgr := config.NewManager("")
	cfg, err := configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Get peer
	peer, err := config.GetPeer(cfg, peerName)
	if err != nil {
		return fmt.Errorf("peer not found: %s", peerName)
	}

	// Check if peer has WireGuard IP
	if peer.WireGuardIP == "" {
		return fmt.Errorf("peer %s does not have a WireGuard IP configured. Please add the peer with: mvpn add %s <public-ip> <wireguard-ip>", peerName, peerName)
	}

	// Get or create ACL rule
	aclRule, err := config.GetACLRule(cfg, peerName)
	if err != nil {
		// Create new rule if it doesn't exist
		aclRule = &types.ACLRule{
			PeerName: peerName,
			Incoming: false,
			Outgoing: false,
		}
	}

	// Update ACL rule
	if direction == "incoming" {
		aclRule.Incoming = true
	} else {
		aclRule.Outgoing = true
	}

	config.UpdateACLRule(cfg, *aclRule)

	// Save configuration
	if err := configMgr.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("ACL rule updated: allowed %s traffic for peer %s\n", direction, peerName)

	// Apply firewall rules if daemon is running
	fwMgr := firewall.NewManager(cfg.InterfaceName)
	wgMgr := wireguard.NewManager(cfg.InterfaceName)

	if wgMgr.InterfaceExists() {
		if direction == "incoming" {
			if err := fwMgr.AllowIncoming(peer.WireGuardIP); err != nil {
				fmt.Printf("Warning: failed to apply firewall rule immediately: %v\n", err)
				fmt.Printf("Rule will be applied when daemon restarts\n")
			} else {
				fmt.Printf("Firewall rule applied immediately\n")
			}
		} else {
			if err := fwMgr.AllowOutgoing(peer.WireGuardIP); err != nil {
				fmt.Printf("Warning: failed to apply firewall rule immediately: %v\n", err)
				fmt.Printf("Rule will be applied when daemon restarts\n")
			} else {
				fmt.Printf("Firewall rule applied immediately\n")
			}
		}
	} else {
		fmt.Printf("Note: Daemon is not running. Firewall rules will be applied when you start the daemon.\n")
	}

	return nil
}
