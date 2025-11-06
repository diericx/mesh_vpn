package commands

import (
	"fmt"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/wireguard"
)

// Init initializes a new node configuration
func Init(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: mvpn init <name> <wireguard-ip>")
	}

	nodeName := args[0]
	wireGuardIP := args[1]

	// Create config manager
	configMgr := config.NewManager("")

	// Check if already initialized
	if _, err := configMgr.Load(); err == nil {
		return fmt.Errorf("node already initialized, config exists at %s", config.DefaultConfigDir)
	}

	// Generate WireGuard keys
	privateKey, publicKey, err := wireguard.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keys: %w", err)
	}

	// Initialize configuration
	cfg, err := configMgr.Initialize(nodeName, wireGuardIP)
	if err != nil {
		return fmt.Errorf("failed to initialize config: %w", err)
	}

	cfg.PrivateKey = privateKey
	cfg.PublicKey = publicKey

	// Save configuration
	if err := configMgr.Save(cfg); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Printf("Node initialized successfully!\n")
	fmt.Printf("Name: %s\n", nodeName)
	fmt.Printf("WireGuard IP: %s\n", wireGuardIP)
	fmt.Printf("Public Key: %s\n", publicKey)
	fmt.Printf("Config saved to: %s\n", config.DefaultConfigDir)

	return nil
}
