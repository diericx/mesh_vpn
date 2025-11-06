package commands

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/daemon"
)

// Start starts the mesh VPN daemon
func Start(args []string) error {
	// Load configuration
	configMgr := config.NewManager("")
	cfg, err := configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	fmt.Printf("Starting Mesh VPN daemon for node %s...\n", cfg.Name)

	// Create and start daemon
	d, err := daemon.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create daemon: %w", err)
	}

	if err := d.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %w", err)
	}

	fmt.Printf("Mesh VPN daemon started successfully\n")
	fmt.Printf("WireGuard interface: %s\n", cfg.InterfaceName)
	fmt.Printf("Mesh port: %d\n", cfg.MeshPort)
	fmt.Printf("\nPress Ctrl+C to stop\n")

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	fmt.Printf("\nShutting down...\n")
	if err := d.Stop(); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	fmt.Printf("Mesh VPN daemon stopped\n")

	return nil
}
