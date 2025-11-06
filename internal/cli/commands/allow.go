package commands

import (
	"fmt"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/firewall"
	"github.com/diericx/mesh-vpn/internal/types"
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

	// Apply firewall rules
	fwMgr := firewall.NewManager(cfg.InterfaceName)
	if direction == "incoming" {
		if err := fwMgr.AllowIncoming(peer.WireGuardIP); err != nil {
			return fmt.Errorf("failed to apply firewall rule: %w", err)
		}
	} else {
		if err := fwMgr.AllowOutgoing(peer.WireGuardIP); err != nil {
			return fmt.Errorf("failed to apply firewall rule: %w", err)
		}
	}

	fmt.Printf("Allowed %s traffic for peer %s\n", direction, peerName)

	return nil
}
