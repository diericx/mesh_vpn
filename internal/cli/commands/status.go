package commands

import (
	"fmt"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/wireguard"
)

// Status shows the current node status
func Status(args []string) error {
	// Load configuration
	configMgr := config.NewManager("")
	cfg, err := configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	fmt.Printf("Node Status\n")
	fmt.Printf("===========\n\n")
	fmt.Printf("Name: %s\n", cfg.Name)
	fmt.Printf("WireGuard IP: %s\n", cfg.WireGuardIP)
	fmt.Printf("WireGuard Port: %d\n", cfg.WireGuardPort)
	fmt.Printf("Mesh Port: %d\n", cfg.MeshPort)
	fmt.Printf("Interface: %s\n", cfg.InterfaceName)
	fmt.Printf("Public Key: %s\n", cfg.PublicKey)
	fmt.Printf("\n")

	// Check WireGuard interface status
	wgMgr := wireguard.NewManager(cfg.InterfaceName)
	if wgMgr.InterfaceExists() {
		fmt.Printf("WireGuard Interface: Active\n")

		status, err := wgMgr.GetInterfaceStatus()
		if err == nil {
			fmt.Printf("\n%s\n", status)
		}
	} else {
		fmt.Printf("WireGuard Interface: Inactive\n")
		fmt.Printf("Run 'mvpn start' to activate the interface\n")
	}

	fmt.Printf("\nPeers: %d configured\n", len(cfg.Peers))

	// Count active ACL rules
	incomingCount := 0
	outgoingCount := 0
	for _, rule := range cfg.ACLRules {
		if rule.Incoming {
			incomingCount++
		}
		if rule.Outgoing {
			outgoingCount++
		}
	}

	fmt.Printf("ACL Rules: %d incoming, %d outgoing\n", incomingCount, outgoingCount)

	return nil
}
