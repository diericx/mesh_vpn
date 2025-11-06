# Mesh VPN

A decentralized mesh VPN built on WireGuard with automatic NAT traversal using STUN.

## Features

- **Decentralized Architecture**: No central server required
- **WireGuard-based**: Leverages the security and performance of WireGuard
- **Automatic NAT Traversal**: Uses STUN protocol for peer-to-peer connections behind NAT
- **Access Control Lists**: Fine-grained control over incoming and outgoing traffic per peer
- **Simple CLI**: Easy-to-use command-line interface
- **Mesh Topology**: Automatic peer discovery and connection management

## Requirements

- Linux operating system
- WireGuard installed (`wg` and `wg-quick` commands available)
- iptables for firewall management
- Root/sudo access for network configuration

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/diericx/mesh-vpn.git
cd mesh-vpn

# Build the binary
make build

# Install (requires sudo)
sudo make install
```

## Quick Start

### 1. Initialize a Node

On each server, initialize the mesh VPN node:

```bash
# On server S1
sudo mvpn init S1 10.0.0.1/24

# On server S2
sudo mvpn init S2 10.0.0.2/24

# On server S3
sudo mvpn init S3 10.0.0.3/24
```

### 2. Start the Daemon

Start the mesh VPN daemon on each node:

```bash
sudo mvpn start
```

### 3. Add Peers

Add other nodes as peers (using their public IP addresses):

```bash
# On S2, add S1
sudo mvpn add S1 24.156.199.1

# On S1, add S2
sudo mvpn add S2 24.156.199.2
```

### 4. Configure Access Control

By default, all traffic is blocked. Allow traffic between peers:

```bash
# On S2, allow traffic to/from S1
sudo mvpn allow incoming S1
sudo mvpn allow outgoing S1

# On S1, allow traffic to/from S2
sudo mvpn allow incoming S2
sudo mvpn allow outgoing S2
```

### 5. List Peers

View all configured peers and their status:

```bash
sudo mvpn ls
```

## Usage

### Commands

- `mvpn init <name> <wireguard-ip>` - Initialize a new node
- `mvpn start` - Start the mesh VPN daemon
- `mvpn stop` - Stop the mesh VPN daemon
- `mvpn add <name> <public-ip>` - Add a peer
- `mvpn remove <name>` - Remove a peer
- `mvpn allow <incoming|outgoing> <peer>` - Allow traffic
- `mvpn deny <incoming|outgoing> <peer>` - Deny traffic
- `mvpn ls` - List all peers
- `mvpn status` - Show node status

### Example Workflow

```bash
# Server S1 (has open port 4949)
sudo mvpn init S1 10.0.0.1/24
sudo mvpn start

# Server S2 (behind NAT)
sudo mvpn init S2 10.0.0.2/24
sudo mvpn start
sudo mvpn add S1 24.156.199.1
sudo mvpn allow incoming S1
sudo mvpn allow outgoing S1

# On S1, add S2
sudo mvpn add S2 24.156.199.2
sudo mvpn allow incoming S2
sudo mvpn allow outgoing S2

# Server S3 (behind NAT)
sudo mvpn init S3 10.0.0.3/24
sudo mvpn start
sudo mvpn add S1 24.156.199.1
sudo mvpn allow incoming S1
sudo mvpn allow outgoing S1

# S3 can now see S2 in the network
sudo mvpn ls

# Add S2 (will use S1 as STUN broker for NAT traversal)
sudo mvpn add S2 24.156.199.2
sudo mvpn allow incoming S2
sudo mvpn allow outgoing S2
```

## Architecture

### Components

1. **WireGuard Management**: Manages WireGuard interface and peer configurations
2. **Mesh Protocol**: UDP-based protocol for peer discovery and coordination
3. **STUN Server**: Provides NAT traversal for peers behind NAT
4. **Firewall Manager**: Manages iptables rules for ACL enforcement
5. **Configuration Manager**: Handles persistent storage of node and peer data

### Network Ports

- **WireGuard Port**: 51820 (default, configurable)
- **Mesh Protocol Port**: 4949 (default, configurable)

### Configuration

Configuration is stored in `/etc/mesh-vpn/config.json` and includes:

- Node information (name, keys, IPs)
- Peer list with connection details
- ACL rules for each peer

## Security Considerations

- All WireGuard traffic is encrypted using the WireGuard protocol
- Default deny policy: all traffic is blocked until explicitly allowed
- Each peer requires manual addition and ACL configuration
- Private keys are stored in `/etc/mesh-vpn/config.json` with 0600 permissions

## Troubleshooting

### Check Node Status

```bash
sudo mvpn status
```

### View WireGuard Interface

```bash
sudo wg show
```

### Check Firewall Rules

```bash
sudo iptables -L MESH_VPN_INPUT -n -v
sudo iptables -L MESH_VPN_OUTPUT -n -v
```

### View Logs

The daemon runs in the foreground when started with `mvpn start`. Check the terminal output for logs.

## Development

### Building

```bash
make build
```

### Testing

```bash
make test
```

### Cleaning

```bash
make clean
```

## License

[Add your license here]

## Contributing

[Add contribution guidelines here]
