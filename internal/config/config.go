package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/diericx/mesh-vpn/internal/types"
)

const (
	DefaultConfigDir     = "/etc/mesh-vpn"
	DefaultConfigFile    = "config.json"
	DefaultWireGuardPort = 51820
	DefaultMeshPort      = 4949
	DefaultInterfaceName = "wg-mesh"
)

// Manager handles configuration persistence
type Manager struct {
	configPath string
}

// NewManager creates a new configuration manager
func NewManager(configDir string) *Manager {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	return &Manager{
		configPath: filepath.Join(configDir, DefaultConfigFile),
	}
}

// Load reads the configuration from disk
func (m *Manager) Load() (*types.NodeConfig, error) {
	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("configuration file not found: %s", m.configPath)
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config types.NodeConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// Save writes the configuration to disk
func (m *Manager) Save(config *types.NodeConfig) error {
	// Ensure config directory exists
	configDir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// Initialize creates a new configuration with default values
func (m *Manager) Initialize(nodeName, wireGuardIP string) (*types.NodeConfig, error) {
	// Check if config already exists
	if _, err := os.Stat(m.configPath); err == nil {
		return nil, fmt.Errorf("configuration already exists at %s", m.configPath)
	}

	config := &types.NodeConfig{
		Name:          nodeName,
		WireGuardIP:   wireGuardIP,
		WireGuardPort: DefaultWireGuardPort,
		MeshPort:      DefaultMeshPort,
		InterfaceName: DefaultInterfaceName,
		Peers:         []types.Peer{},
		ACLRules:      []types.ACLRule{},
	}

	return config, nil
}

// GetPeer retrieves a peer by name
func GetPeer(config *types.NodeConfig, name string) (*types.Peer, error) {
	for i := range config.Peers {
		if config.Peers[i].Name == name {
			return &config.Peers[i], nil
		}
	}
	return nil, fmt.Errorf("peer not found: %s", name)
}

// AddPeer adds a new peer to the configuration
func AddPeer(config *types.NodeConfig, peer types.Peer) error {
	// Check if peer already exists
	for _, p := range config.Peers {
		if p.Name == peer.Name {
			return fmt.Errorf("peer already exists: %s", peer.Name)
		}
	}
	config.Peers = append(config.Peers, peer)
	return nil
}

// RemovePeer removes a peer from the configuration
func RemovePeer(config *types.NodeConfig, name string) error {
	for i, p := range config.Peers {
		if p.Name == name {
			config.Peers = append(config.Peers[:i], config.Peers[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("peer not found: %s", name)
}

// GetACLRule retrieves an ACL rule for a peer
func GetACLRule(config *types.NodeConfig, peerName string) (*types.ACLRule, error) {
	for i := range config.ACLRules {
		if config.ACLRules[i].PeerName == peerName {
			return &config.ACLRules[i], nil
		}
	}
	return nil, fmt.Errorf("ACL rule not found for peer: %s", peerName)
}

// UpdateACLRule updates or creates an ACL rule for a peer
func UpdateACLRule(config *types.NodeConfig, rule types.ACLRule) {
	for i := range config.ACLRules {
		if config.ACLRules[i].PeerName == rule.PeerName {
			config.ACLRules[i] = rule
			return
		}
	}
	config.ACLRules = append(config.ACLRules, rule)
}

// RemoveACLRule removes an ACL rule for a peer
func RemoveACLRule(config *types.NodeConfig, peerName string) error {
	for i, rule := range config.ACLRules {
		if rule.PeerName == peerName {
			config.ACLRules = append(config.ACLRules[:i], config.ACLRules[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("ACL rule not found for peer: %s", peerName)
}
