package firewall

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/diericx/mesh-vpn/internal/types"
)

const (
	ChainInput   = "MESH_VPN_INPUT"
	ChainOutput  = "MESH_VPN_OUTPUT"
	ChainForward = "MESH_VPN_FORWARD"
)

// Manager handles iptables firewall rules
type Manager struct {
	interfaceName string
}

// NewManager creates a new firewall manager
func NewManager(interfaceName string) *Manager {
	return &Manager{
		interfaceName: interfaceName,
	}
}

// Initialize sets up the custom iptables chains
func (m *Manager) Initialize() error {
	// Create custom chains if they don't exist
	chains := []string{ChainInput, ChainOutput, ChainForward}
	for _, chain := range chains {
		// Try to create chain (ignore error if it already exists)
		exec.Command("iptables", "-N", chain).Run()
	}

	// Link custom chains to main chains
	if err := m.ensureJumpRule("INPUT", ChainInput); err != nil {
		return fmt.Errorf("failed to link INPUT chain: %w", err)
	}
	if err := m.ensureJumpRule("OUTPUT", ChainOutput); err != nil {
		return fmt.Errorf("failed to link OUTPUT chain: %w", err)
	}
	if err := m.ensureJumpRule("FORWARD", ChainForward); err != nil {
		return fmt.Errorf("failed to link FORWARD chain: %w", err)
	}

	// Set default policy to DROP for our custom chains
	for _, chain := range chains {
		cmd := exec.Command("iptables", "-P", chain, "DROP")
		// Ignore error as custom chains can't have policies, we'll use explicit DROP rules
		cmd.Run()
	}

	// Add default DROP rules at the end of each custom chain
	for _, chain := range chains {
		m.addDropRule(chain)
	}

	return nil
}

// ensureJumpRule ensures a jump rule exists from mainChain to customChain
func (m *Manager) ensureJumpRule(mainChain, customChain string) error {
	// Determine interface flag based on chain type
	interfaceFlag := "-i"
	if mainChain == "OUTPUT" {
		interfaceFlag = "-o"
	}

	// Check if rule already exists
	cmd := exec.Command("iptables", "-C", mainChain, interfaceFlag, m.interfaceName, "-j", customChain)
	if err := cmd.Run(); err == nil {
		return nil // Rule already exists
	}

	// Add the jump rule
	cmd = exec.Command("iptables", "-I", mainChain, "1", interfaceFlag, m.interfaceName, "-j", customChain)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add jump rule: %w", err)
	}

	return nil
}

// addDropRule adds a default DROP rule at the end of a chain
func (m *Manager) addDropRule(chain string) error {
	// Remove existing DROP rule if present
	cmd := exec.Command("iptables", "-D", chain, "-j", "DROP")
	cmd.Run() // Ignore error

	// Add DROP rule at the end
	cmd = exec.Command("iptables", "-A", chain, "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add DROP rule: %w", err)
	}

	return nil
}

// ApplyACLRules applies all ACL rules for the given configuration
func (m *Manager) ApplyACLRules(config *types.NodeConfig) error {
	// Clear existing rules (except jump rules and default DROP)
	if err := m.ClearRules(); err != nil {
		return fmt.Errorf("failed to clear existing rules: %w", err)
	}

	// Apply each ACL rule
	for _, rule := range config.ACLRules {
		peer, err := getPeerByName(config, rule.PeerName)
		if err != nil {
			continue // Skip if peer not found
		}

		if rule.Incoming {
			if err := m.AllowIncoming(peer.WireGuardIP); err != nil {
				return fmt.Errorf("failed to allow incoming from %s: %w", rule.PeerName, err)
			}
		}

		if rule.Outgoing {
			if err := m.AllowOutgoing(peer.WireGuardIP); err != nil {
				return fmt.Errorf("failed to allow outgoing to %s: %w", rule.PeerName, err)
			}
		}
	}

	return nil
}

// AllowIncoming allows incoming traffic from a specific IP
func (m *Manager) AllowIncoming(sourceIP string) error {
	// Insert rule before the DROP rule
	cmd := exec.Command("iptables", "-I", ChainInput, "1",
		"-s", sourceIP,
		"-i", m.interfaceName,
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add incoming rule: %w", err)
	}

	return nil
}

// AllowOutgoing allows outgoing traffic to a specific IP
func (m *Manager) AllowOutgoing(destIP string) error {
	// Insert rule before the DROP rule
	cmd := exec.Command("iptables", "-I", ChainOutput, "1",
		"-d", destIP,
		"-o", m.interfaceName,
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to add outgoing rule: %w", err)
	}

	return nil
}

// BlockIncoming blocks incoming traffic from a specific IP
func (m *Manager) BlockIncoming(sourceIP string) error {
	cmd := exec.Command("iptables", "-D", ChainInput,
		"-s", sourceIP,
		"-i", m.interfaceName,
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		// Rule might not exist, which is fine
		return nil
	}

	return nil
}

// BlockOutgoing blocks outgoing traffic to a specific IP
func (m *Manager) BlockOutgoing(destIP string) error {
	cmd := exec.Command("iptables", "-D", ChainOutput,
		"-d", destIP,
		"-o", m.interfaceName,
		"-j", "ACCEPT")

	if err := cmd.Run(); err != nil {
		// Rule might not exist, which is fine
		return nil
	}

	return nil
}

// ClearRules removes all rules from custom chains (except default DROP)
func (m *Manager) ClearRules() error {
	chains := []string{ChainInput, ChainOutput, ChainForward}

	for _, chain := range chains {
		// Flush all rules
		cmd := exec.Command("iptables", "-F", chain)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to flush chain %s: %w", chain, err)
		}

		// Re-add default DROP rule
		if err := m.addDropRule(chain); err != nil {
			return err
		}
	}

	return nil
}

// Cleanup removes all custom chains and rules
func (m *Manager) Cleanup() error {
	chains := []string{ChainInput, ChainOutput, ChainForward}

	// Remove jump rules from main chains
	exec.Command("iptables", "-D", "INPUT", "-i", m.interfaceName, "-j", ChainInput).Run()
	exec.Command("iptables", "-D", "OUTPUT", "-o", m.interfaceName, "-j", ChainOutput).Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", m.interfaceName, "-j", ChainForward).Run()

	// Flush and delete custom chains
	for _, chain := range chains {
		exec.Command("iptables", "-F", chain).Run()
		exec.Command("iptables", "-X", chain).Run()
	}

	return nil
}

// ListRules returns the current iptables rules for the mesh VPN
func (m *Manager) ListRules() (string, error) {
	var output strings.Builder
	chains := []string{ChainInput, ChainOutput, ChainForward}

	for _, chain := range chains {
		cmd := exec.Command("iptables", "-L", chain, "-n", "-v")
		out, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("failed to list rules for chain %s: %w", chain, err)
		}
		output.WriteString(fmt.Sprintf("\n=== %s ===\n", chain))
		output.Write(out)
	}

	return output.String(), nil
}

// Helper function to get peer by name
func getPeerByName(config *types.NodeConfig, name string) (*types.Peer, error) {
	for i := range config.Peers {
		if config.Peers[i].Name == name {
			return &config.Peers[i], nil
		}
	}
	return nil, fmt.Errorf("peer not found: %s", name)
}
