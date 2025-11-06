package cli

import (
	"fmt"
	"os"

	"github.com/diericx/mesh-vpn/internal/cli/commands"
)

// Execute runs the CLI
func Execute() error {
	if len(os.Args) < 2 {
		printUsage()
		return nil
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "init":
		return commands.Init(args)
	case "start":
		return commands.Start(args)
	case "stop":
		return commands.Stop(args)
	case "add":
		return commands.Add(args)
	case "remove":
		return commands.Remove(args)
	case "allow":
		return commands.Allow(args)
	case "deny":
		return commands.Deny(args)
	case "ls", "list":
		return commands.List(args)
	case "status":
		return commands.Status(args)
	case "help":
		printUsage()
		return nil
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		return fmt.Errorf("unknown command: %s", command)
	}
}

func printUsage() {
	usage := `Mesh VPN - Decentralized WireGuard Mesh Network

Usage:
  mvpn <command> [arguments]

Commands:
  init <name> <wireguard-ip>              Initialize a new node configuration
  start                                   Start the mesh VPN daemon
  stop                                    Stop the mesh VPN daemon
  add <name> <public-ip> <wireguard-ip>   Add a new peer to the network
  remove <name>                           Remove a peer from the network
  allow <direction> <peer>                Allow traffic (direction: incoming/outgoing)
  deny <direction> <peer>                 Deny traffic (direction: incoming/outgoing)
  ls, list                                List all known peers and their status
  status                                  Show current node status
  help                                    Show this help message

Examples:
  # Initialize node S1 with WireGuard IP 10.0.0.1/24
  mvpn init S1 10.0.0.1/24

  # Start the mesh VPN daemon
  mvpn start

  # Add peer S2 with public IP 24.156.199.2 and WireGuard IP 10.0.0.2/24
  mvpn add S2 24.156.199.2 10.0.0.2/24

  # Allow incoming traffic from S2
  mvpn allow incoming S2

  # Allow outgoing traffic to S2
  mvpn allow outgoing S2

  # List all peers
  mvpn ls

  # Show node status
  mvpn status
`
	fmt.Print(usage)
}
