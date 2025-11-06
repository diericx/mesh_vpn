package commands

import (
	"fmt"
	"time"

	"github.com/diericx/mesh-vpn/internal/config"
)

// List lists all known peers and their status
func List(args []string) error {
	// Load configuration
	configMgr := config.NewManager("")
	cfg, err := configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	if len(cfg.Peers) == 0 {
		fmt.Println("No peers configured")
		return nil
	}

	fmt.Printf("Known peers for node %s:\n\n", cfg.Name)

	for _, peer := range cfg.Peers {
		// Get ACL rule
		aclRule, err := config.GetACLRule(cfg, peer.Name)

		status := "disconnected"
		if time.Since(peer.LastSeen) < 2*time.Minute {
			status = "connected"
		}

		fmt.Printf("%-15s", peer.Name)
		fmt.Printf(" (%s)", status)

		if err == nil {
			if aclRule.Incoming && aclRule.Outgoing {
				fmt.Printf(" [bidirectional]")
			} else if aclRule.Incoming {
				fmt.Printf(" [incoming only]")
			} else if aclRule.Outgoing {
				fmt.Printf(" [outgoing only]")
			} else {
				fmt.Printf(" [blocked]")
			}
		}

		fmt.Println()

		if peer.PublicIP != "" {
			fmt.Printf("  Public IP: %s\n", peer.PublicIP)
		}
		if peer.WireGuardIP != "" {
			fmt.Printf("  WireGuard IP: %s\n", peer.WireGuardIP)
		}
		if peer.PublicKey != "" {
			fmt.Printf("  Public Key: %s\n", peer.PublicKey)
		}
		if peer.HasOpenPort {
			fmt.Printf("  Has Open Port: Yes\n")
		}
		fmt.Println()
	}

	return nil
}
