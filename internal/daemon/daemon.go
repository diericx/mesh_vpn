package daemon

import (
	"fmt"
	"sync"

	"github.com/diericx/mesh-vpn/internal/config"
	"github.com/diericx/mesh-vpn/internal/firewall"
	"github.com/diericx/mesh-vpn/internal/mesh"
	"github.com/diericx/mesh-vpn/internal/stun"
	"github.com/diericx/mesh-vpn/internal/types"
	"github.com/diericx/mesh-vpn/internal/wireguard"
)

// Daemon manages the mesh VPN service
type Daemon struct {
	config     *types.NodeConfig
	configMgr  *config.Manager
	wgMgr      *wireguard.Manager
	fwMgr      *firewall.Manager
	meshProto  *mesh.Protocol
	stunServer *stun.Server
	stopChan   chan struct{}
	wg         sync.WaitGroup
}

// New creates a new daemon instance
func New(cfg *types.NodeConfig) (*Daemon, error) {
	return &Daemon{
		config:     cfg,
		configMgr:  config.NewManager(""),
		wgMgr:      wireguard.NewManager(cfg.InterfaceName),
		fwMgr:      firewall.NewManager(cfg.InterfaceName),
		meshProto:  mesh.NewProtocol(cfg),
		stunServer: stun.NewServer(cfg),
		stopChan:   make(chan struct{}),
	}, nil
}

// Start starts all daemon components
func (d *Daemon) Start() error {
	// Initialize firewall
	if err := d.fwMgr.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize firewall: %w", err)
	}

	// Create WireGuard interface if it doesn't exist
	if !d.wgMgr.InterfaceExists() {
		if err := d.wgMgr.CreateInterface(
			d.config.PrivateKey,
			d.config.WireGuardPort,
			d.config.WireGuardIP,
		); err != nil {
			return fmt.Errorf("failed to create WireGuard interface: %w", err)
		}
	}

	// Add all configured peers to WireGuard
	for i := range d.config.Peers {
		peer := &d.config.Peers[i]
		if peer.PublicKey != "" {
			if err := d.wgMgr.AddPeer(peer); err != nil {
				fmt.Printf("Warning: failed to add peer %s to WireGuard: %v\n", peer.Name, err)
			}
		}
	}

	// Apply ACL rules
	if err := d.fwMgr.ApplyACLRules(d.config); err != nil {
		return fmt.Errorf("failed to apply ACL rules: %w", err)
	}

	// Start mesh protocol
	if err := d.meshProto.Start(); err != nil {
		return fmt.Errorf("failed to start mesh protocol: %w", err)
	}

	// Start STUN server (uses mesh protocol's connection)
	if err := d.stunServer.Start(d.meshProto); err != nil {
		return fmt.Errorf("failed to start STUN server: %w", err)
	}

	// Announce presence to the network
	if err := d.meshProto.AnnouncePresence(); err != nil {
		fmt.Printf("Warning: failed to announce presence: %v\n", err)
	}

	return nil
}

// Stop stops all daemon components
func (d *Daemon) Stop() error {
	close(d.stopChan)

	// Stop mesh protocol
	if err := d.meshProto.Stop(); err != nil {
		fmt.Printf("Warning: failed to stop mesh protocol: %v\n", err)
	}

	// Stop STUN server
	if err := d.stunServer.Stop(); err != nil {
		fmt.Printf("Warning: failed to stop STUN server: %v\n", err)
	}

	// Clean up firewall rules
	if err := d.fwMgr.Cleanup(); err != nil {
		fmt.Printf("Warning: failed to cleanup firewall: %v\n", err)
	}

	// Delete WireGuard interface
	if d.wgMgr.InterfaceExists() {
		if err := d.wgMgr.DeleteInterface(); err != nil {
			fmt.Printf("Warning: failed to delete WireGuard interface: %v\n", err)
		}
	}

	d.wg.Wait()

	return nil
}

// Reload reloads the configuration and applies changes
func (d *Daemon) Reload() error {
	cfg, err := d.configMgr.Load()
	if err != nil {
		return fmt.Errorf("failed to reload config: %w", err)
	}

	d.config = cfg

	// Reapply ACL rules
	if err := d.fwMgr.ApplyACLRules(cfg); err != nil {
		return fmt.Errorf("failed to apply ACL rules: %w", err)
	}

	// Update WireGuard peers
	for i := range cfg.Peers {
		peer := &cfg.Peers[i]
		if peer.PublicKey != "" {
			if err := d.wgMgr.UpdatePeer(peer); err != nil {
				fmt.Printf("Warning: failed to update peer %s: %v\n", peer.Name, err)
			}
		}
	}

	return nil
}
