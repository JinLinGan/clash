package constant

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
)

// Adapter Type
const (
	Direct AdapterType = iota
	Reject

	Shadowsocks
	ShadowsocksR
	Snell
	Socks5
	Http
	Vmess
	Trojan
	Ssh

	Relay
	Selector
	Fallback
	URLTest
	LoadBalance
	AutoSelector
)

const (
	DefaultTCPTimeout = 5 * time.Second
	DefaultUDPTimeout = DefaultTCPTimeout
	DefaultTLSTimeout = DefaultTCPTimeout
)

type Connection interface {
	Chains() Chain
	AppendToChains(adapter ProxyAdapter)
}

type Chain []string

func (c Chain) String() string {
	switch len(c) {
	case 0:
		return ""
	case 1:
		return c[0]
	default:
		return fmt.Sprintf("%s[%s]", c[len(c)-1], c[0])
	}
}

func (c Chain) Last() string {
	switch len(c) {
	case 0:
		return ""
	default:
		return c[0]
	}
}

type Conn interface {
	net.Conn
	Connection
}

type PacketConn interface {
	net.PacketConn
	Connection
	// Deprecate WriteWithMetadata because of remote resolve DNS cause TURN failed
	// WriteWithMetadata(p []byte, metadata *Metadata) (n int, err error)
}

type ProxyAdapter interface {
	Name() string
	Type() AdapterType
	Addr() string
	SupportUDP() bool
	MarshalJSON() ([]byte, error)

	// StreamConn wraps a protocol around net.Conn with Metadata.
	//
	// Examples:
	//	conn, _ := net.DialContext(context.Background(), "tcp", "host:port")
	//	conn, _ = adapter.StreamConn(conn, metadata)
	//
	// It returns a C.Conn with protocol which start with
	// a new session (if any)
	StreamConn(c net.Conn, metadata *Metadata) (net.Conn, error)

	// DialContext return a C.Conn with protocol which
	// contains multiplexing-related reuse logic (if any)
	DialContext(ctx context.Context, metadata *Metadata, opts ...dialer.Option) (Conn, error)
	ListenPacketContext(ctx context.Context, metadata *Metadata, opts ...dialer.Option) (PacketConn, error)

	// Unwrap extracts the proxy from a proxy-group. It returns nil when nothing to extract.
	Unwrap(metadata *Metadata) Proxy
}

type DelayHistory struct {
	Time  time.Time `json:"time"`
	Delay uint16    `json:"delay"`
}

type Proxy interface {
	ProxyAdapter
	Alive() bool
	DelayHistory() []DelayHistory
	LastDelay() uint16
	URLTest(ctx context.Context, url string) (uint16, error)

	// Deprecated: use DialContext instead.
	Dial(metadata *Metadata) (Conn, error)

	// Deprecated: use DialPacketConn instead.
	DialUDP(metadata *Metadata) (PacketConn, error)
}
type InboundType uint8

const (
	InboundTypeHTTP InboundType = iota
	InboundTypeSOCKS
	InboundTypeDirect
)

func (t InboundType) String() string {
	return [...]string{"http", "socks", "direct"}[t]
}

func (t *InboundType) FromString(kind string) InboundType {
	return map[string]InboundType{
		"http":   InboundTypeHTTP,
		"socks":  InboundTypeSOCKS,
		"direct": InboundTypeDirect,
	}[kind]
}

func (t InboundType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *InboundType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	*t = t.FromString(s)
	return nil
}

type ProxyType uint8

const (
	ProxyTypeDirect ProxyType = iota
	ProxyTypeHttp
	ProxyTypeReject
	ProxyTypeShadowSocks
	ProxyTypeShadowSocksR
	ProxyTypeSnell
	ProxyTypeSocks5
	ProxyTypeTrojan
	ProxyTypeVmess
	ProxyTypeSsh
)

func (t ProxyType) String() string {
	return [...]string{"direct", "http", "reject", "ss", "ssr", "snell", "socks5", "trojan", "vmess", "ssh"}[t]
}

func (t *ProxyType) FromString(kind string) ProxyType {
	return map[string]ProxyType{
		"direct": ProxyTypeDirect,
		"http":   ProxyTypeHttp,
		"reject": ProxyTypeReject,
		"ss":     ProxyTypeShadowSocks,
		"ssr":    ProxyTypeShadowSocksR,
		"snell":  ProxyTypeSnell,
		"socks5": ProxyTypeSocks5,
		"trojan": ProxyTypeTrojan,
		"vmess":  ProxyTypeVmess,
		"ssh":    ProxyTypeSsh,
	}[kind]
}

func (t ProxyType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *ProxyType) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	*t = t.FromString(s)
	return nil
}

type Inbound interface {
	Name() string
	Type() InboundType
	RawAddress() string
	GetRawConfigString() string
	Close()
}

// AdapterType is enum of adapter type
type AdapterType int

func (at AdapterType) String() string {
	switch at {
	case Direct:
		return "Direct"
	case Reject:
		return "Reject"

	case Shadowsocks:
		return "Shadowsocks"
	case ShadowsocksR:
		return "ShadowsocksR"
	case Snell:
		return "Snell"
	case Socks5:
		return "Socks5"
	case Ssh:
		return "Ssh"
	case Http:
		return "Http"
	case Vmess:
		return "Vmess"
	case Trojan:
		return "Trojan"

	case Relay:
		return "Relay"
	case Selector:
		return "Selector"
	case Fallback:
		return "Fallback"
	case URLTest:
		return "URLTest"
	case LoadBalance:
		return "LoadBalance"
	case AutoSelector:
		return "AutoSelector"

	default:
		return "Unknown"
	}
}

// UDPPacket contains the data of UDP packet, and offers control/info of UDP packet's source
type UDPPacket interface {
	// Data get the payload of UDP Packet
	Data() []byte

	// WriteBack writes the payload with source IP/Port equals addr
	// - variable source IP/Port is important to STUN
	// - if addr is not provided, WriteBack will write out UDP packet with SourceIP/Port equals to original Target,
	//   this is important when using Fake-IP.
	WriteBack(b []byte, addr net.Addr) (n int, err error)

	// Drop call after packet is used, could recycle buffer in this function.
	Drop()

	// LocalAddr returns the source IP/Port of packet
	LocalAddr() net.Addr
}
