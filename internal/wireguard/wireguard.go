package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/diericx/mesh-vpn/internal/types"
)

// Manager handles WireGuard interface operations
type Manager struct {
	interfaceName string
}

// NewManager creates a new WireGuard manager
func NewManager(interfaceName string) *Manager {
	return &Manager{
		interfaceName: interfaceName,
	}
}

// GenerateKeyPair generates a new WireGuard key pair
func GenerateKeyPair() (privateKey, publicKey string, err error) {
	// Generate private key
	cmd := exec.Command("wg", "genkey")
	privateKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	privateKey = strings.TrimSpace(string(privateKeyBytes))

	// Generate public key from private key
	cmd = exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	publicKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey = strings.TrimSpace(string(publicKeyBytes))

	return privateKey, publicKey, nil
}

// CreateInterface creates a new WireGuard interface
func (m *Manager) CreateInterface(privateKey string, listenPort int, address string) error {
	// Create interface
	cmd := exec.Command("ip", "link", "add", "dev", m.interfaceName, "type", "wireguard")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Set private key
	cmd = exec.Command("wg", "set", m.interfaceName, "private-key", "/dev/stdin", "listen-port", fmt.Sprintf("%d", listenPort))
	cmd.Stdin = strings.NewReader(privateKey)
	if err := cmd.Run(); err != nil {
		m.DeleteInterface() // Cleanup on failure
		return fmt.Errorf("failed to set private key: %w", err)
	}

	// Assign IP address
	cmd = exec.Command("ip", "address", "add", "dev", m.interfaceName, address)
	if err := cmd.Run(); err != nil {
		m.DeleteInterface() // Cleanup on failure
		return fmt.Errorf("failed to assign IP address: %w", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "up", "dev", m.interfaceName)
	if err := cmd.Run(); err != nil {
		m.DeleteInterface() // Cleanup on failure
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// DeleteInterface removes the WireGuard interface
func (m *Manager) DeleteInterface() error {
	cmd := exec.Command("ip", "link", "delete", "dev", m.interfaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to delete interface: %w", err)
	}
	return nil
}

// AddPeer adds a peer to the WireGuard interface
func (m *Manager) AddPeer(peer *types.Peer) error {
	args := []string{"set", m.interfaceName, "peer", peer.PublicKey}

	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}

	if len(peer.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
	}

	if peer.PersistentKA > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprintf("%d", peer.PersistentKA))
	}

	cmd := exec.Command("wg", args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add peer: %w", err)
	}

	return nil
}

// RemovePeer removes a peer from the WireGuard interface
func (m *Manager) RemovePeer(publicKey string) error {
	cmd := exec.Command("wg", "set", m.interfaceName, "peer", publicKey, "remove")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to remove peer: %w", err)
	}
	return nil
}

// UpdatePeer updates a peer's configuration
func (m *Manager) UpdatePeer(peer *types.Peer) error {
	// WireGuard updates are done by re-adding the peer with new settings
	return m.AddPeer(peer)
}

// GetInterfaceStatus returns the current status of the WireGuard interface
func (m *Manager) GetInterfaceStatus() (string, error) {
	cmd := exec.Command("wg", "show", m.interfaceName)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to get interface status: %w", err)
	}
	return string(output), nil
}

// InterfaceExists checks if the WireGuard interface exists
func (m *Manager) InterfaceExists() bool {
	cmd := exec.Command("ip", "link", "show", m.interfaceName)
	err := cmd.Run()
	return err == nil
}

// WriteConfigFile writes a WireGuard configuration file
func (m *Manager) WriteConfigFile(config *types.NodeConfig, configPath string) error {
	var sb strings.Builder

	// Interface section
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", config.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", config.WireGuardIP))
	sb.WriteString(fmt.Sprintf("ListenPort = %d\n", config.WireGuardPort))
	sb.WriteString("\n")

	// Peer sections
	for _, peer := range config.Peers {
		sb.WriteString("[Peer]\n")
		sb.WriteString(fmt.Sprintf("PublicKey = %s\n", peer.PublicKey))

		if peer.Endpoint != "" {
			sb.WriteString(fmt.Sprintf("Endpoint = %s\n", peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", strings.Join(peer.AllowedIPs, ", ")))
		}

		if peer.PersistentKA > 0 {
			sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKA))
		}

		sb.WriteString("\n")
	}

	if err := os.WriteFile(configPath, []byte(sb.String()), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}
