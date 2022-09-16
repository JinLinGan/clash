package otherinbound

import (
	"io"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/adapter/inbound"
	N "github.com/Dreamacro/clash/common/net"
	"github.com/Dreamacro/clash/common/pool"
	"github.com/Dreamacro/clash/component/auth"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"
	"github.com/Dreamacro/clash/transport/socks4"
	"github.com/Dreamacro/clash/transport/socks5"
)

type SocksOption struct {
	BaseOption
	Users []User `json:"users,omitempty"`
}

type Socks struct {
	Base
	Listener      *Listener
	UDPListener   *UDPListener
	tcpIn         chan<- C.ConnContext
	udpIn         chan<- *inbound.PacketAdapter
	Authenticator auth.Authenticator
}

func (s *Socks) run() error {
	tcpListener, err := NewTCP(s.addr, s.handleSocks)
	if err != nil {
		return err
	}
	log.Infoln("SOCKS OtherInbound %s listening at: %s", s.Base.inboundName, tcpListener.Address())

	udpListener, err := NewUDP(s.addr, s.handleSocksUDP)
	if err != nil {
		tcpListener.Close()
		return err
	}

	s.Listener = tcpListener
	s.UDPListener = udpListener

	return nil
}

func (s *Socks) Close() {
	s.Listener.Close()
	s.UDPListener.Close()
	log.Infoln("SOCKS OtherInbound %s closed", s.Base.inboundName)
}

func (s *Socks) handleSocks(conn net.Conn) {
	conn.(*net.TCPConn).SetKeepAlive(true)
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	switch head[0] {
	case socks4.Version:
		s.HandleSocks4(bufConn)
	case socks5.Version:
		s.HandleSocks5(bufConn)
	default:
		conn.Close()
	}
}

func (s *Socks) HandleSocks4(conn net.Conn) {
	addr, _, err := socks4.ServerHandshake(conn, s.Authenticator)
	if err != nil {
		conn.Close()
		return
	}
	connContext := inbound.NewSocket(socks5.ParseAddr(addr), conn, C.SOCKS4)
	connContext.Metadata().Inbound = s.inboundName

	s.tcpIn <- connContext
}

func (s *Socks) HandleSocks5(conn net.Conn) {
	target, command, err := socks5.ServerHandshake(conn, s.Authenticator)
	if err != nil {
		conn.Close()
		return
	}
	if command == socks5.CmdUDPAssociate {
		defer conn.Close()
		io.Copy(io.Discard, conn)
		return
	}

	connContext := inbound.NewSocket(target, conn, C.SOCKS5)
	connContext.Metadata().Inbound = s.inboundName
	s.tcpIn <- connContext
}

func (s *Socks) handleSocksUDP(pc net.PacketConn, buf []byte, addr net.Addr) {
	target, payload, err := socks5.DecodeUDPPacket(buf)
	if err != nil {
		// Unresolved UDP packet, return buffer to the pool
		pool.Put(buf)
		return
	}
	packet := &packet{
		pc:      pc,
		rAddr:   addr,
		payload: payload,
		bufRef:  buf,
	}

	packetAdapter := inbound.NewPacket(target, packet, C.SOCKS5)
	packetAdapter.Metadata().Inbound = s.inboundName

	select {
	case s.udpIn <- packetAdapter:
	default:
	}
}

func NewSocks(option SocksOption, tcpIn chan<- C.ConnContext, udpIn chan<- *inbound.PacketAdapter) (*Socks, error) {
	addr := net.JoinHostPort(option.Listen, strconv.Itoa(option.Port))

	var auth auth.Authenticator
	if len(option.Users) > 0 {
		auth = NewAuthenticator(option.Users)
	}
	s := &Socks{
		Base: Base{
			inboundName: option.Name,
			inboundType: C.OtherInboundTypeSocks,
			addr:        addr,
		},
		tcpIn:         tcpIn,
		udpIn:         udpIn,
		Authenticator: auth,
	}

	if err := s.run(); err != nil {
		return nil, err
	}
	return s, nil
}

type UDPListener struct {
	packetConn net.PacketConn
	addr       string
	closed     bool
}

// RawAddress implements C.Listener
func (l *UDPListener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *UDPListener) Address() string {
	return l.packetConn.LocalAddr().String()
}

// Close implements C.Listener
func (l *UDPListener) Close() error {
	l.closed = true
	return l.packetConn.Close()
}

type packet struct {
	pc      net.PacketConn
	rAddr   net.Addr
	payload []byte
	bufRef  []byte
}

func (c *packet) Data() []byte {
	return c.payload
}

// WriteBack write UDP packet with source(ip, port) = `addr`
func (c *packet) WriteBack(b []byte, addr net.Addr) (n int, err error) {
	packet, err := socks5.EncodeUDPPacket(socks5.ParseAddrToSocksAddr(addr), b)
	if err != nil {
		return
	}
	return c.pc.WriteTo(packet, c.rAddr)
}

// LocalAddr returns the source IP/Port of UDP Packet
func (c *packet) LocalAddr() net.Addr {
	return c.rAddr
}

func (c *packet) Drop() {
	pool.Put(c.bufRef)
}
