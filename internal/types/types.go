package types

import (
	"net"
	"time"
)

// MessageHandler is a function that handles incoming mesh messages
type MessageHandler func(msg *MeshMessage, addr *net.UDPAddr) error

// Peer represents a node in the mesh network
type Peer struct {
	Name         string    `json:"name"`
	PublicIP     string    `json:"public_ip"`
	WireGuardIP  string    `json:"wireguard_ip"`
	PublicKey    string    `json:"public_key"`
	ListenPort   int       `json:"listen_port"`
	HasOpenPort  bool      `json:"has_open_port"`
	LastSeen     time.Time `json:"last_seen"`
	Endpoint     string    `json:"endpoint"` // IP:Port for WireGuard
	AllowedIPs   []string  `json:"allowed_ips"`
	PersistentKA int       `json:"persistent_keepalive"`
}

// ACLRule defines access control for a peer
type ACLRule struct {
	PeerName   string   `json:"peer_name"`
	Incoming   bool     `json:"incoming"`              // Allow incoming traffic from this peer
	Outgoing   bool     `json:"outgoing"`              // Allow outgoing traffic to this peer
	AllowedIPs []string `json:"allowed_ips,omitempty"` // Specific IPs/subnets allowed (empty = all)
}

// NodeConfig represents the local node's configuration
type NodeConfig struct {
	Name          string    `json:"name"`
	WireGuardIP   string    `json:"wireguard_ip"`
	WireGuardPort int       `json:"wireguard_port"`
	MeshPort      int       `json:"mesh_port"`
	PrivateKey    string    `json:"private_key"`
	PublicKey     string    `json:"public_key"`
	InterfaceName string    `json:"interface_name"`
	Peers         []Peer    `json:"peers"`
	ACLRules      []ACLRule `json:"acl_rules"`
}

// MeshMessage represents a message in the mesh orchestration protocol
type MeshMessage struct {
	Type      string                 `json:"type"`
	From      string                 `json:"from"`
	To        string                 `json:"to,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// MessageType constants
const (
	MsgTypePeerDiscovery = "peer_discovery"
	MsgTypePeerAnnounce  = "peer_announce"
	MsgTypeKeyExchange   = "key_exchange"
	MsgTypeSTUNRequest   = "stun_request"
	MsgTypeSTUNResponse  = "stun_response"
	MsgTypeHeartbeat     = "heartbeat"
	MsgTypePeerUpdate    = "peer_update"
)

// STUNRequest represents a STUN traversal request
type STUNRequest struct {
	RequesterName string `json:"requester_name"`
	TargetName    string `json:"target_name"`
	BrokerName    string `json:"broker_name"`
}

// STUNResponse contains the discovered endpoint information
type STUNResponse struct {
	RequesterName string `json:"requester_name"`
	TargetName    string `json:"target_name"`
	Endpoint      string `json:"endpoint"` // IP:Port
	Success       bool   `json:"success"`
}

// Connection represents an active connection state
type Connection struct {
	PeerName      string
	LocalAddr     *net.UDPAddr
	RemoteAddr    *net.UDPAddr
	LastHeartbeat time.Time
	IsActive      bool
}
