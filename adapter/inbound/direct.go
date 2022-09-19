package inbound

import (
	"fmt"
	"net"
	"strconv"

	"github.com/Dreamacro/clash/adapter/defaultinbound"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/context"
	"github.com/Dreamacro/clash/log"
)

type Direct struct {
	Base

	Listener    *Listener
	UDPListener *UDPListener
	tcpIn       chan<- C.ConnContext
	udpIn       chan<- *defaultinbound.PacketAdapter

	cacheMeta C.Metadata // 缓存目标meta信息
}

type DirectOption struct {
	Listen       string `yaml:"listen" json:"listen"`
	Port         int    `yaml:"port" json:"port"`
	RedirectAddr string `json:"redirect-addr"` // 重定向地址，把从监听地址收到的数据转发到这个地址
}

func NewDirect(option DirectOption, name string, tcpIn chan<- C.ConnContext, udpIn chan<- *defaultinbound.PacketAdapter) (*Direct, error) {
	addr := net.JoinHostPort(option.Listen, strconv.Itoa(option.Port))

	h, p, err := net.SplitHostPort(option.RedirectAddr)
	if err != nil {
		return nil, fmt.Errorf("address error:%w", err)
	}

	// 创建可复用的meta信息
	meta := C.Metadata{
		NetWork: 0,
		Type:    C.REDIR,
		DstIP:   nil,
		DstPort: p,
		Host:    h,
		Inbound: name,
	}
	if ip := net.ParseIP(h); ip != nil {
		meta.DstIP = ip
	}

	s := &Direct{
		Base: Base{
			inboundName: name,
			inboundType: C.DIRECTInbound,
			addr:        addr,
		},
		tcpIn:     tcpIn,
		udpIn:     udpIn,
		cacheMeta: meta,
	}

	if err := s.run(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Direct) handleTCP(conn net.Conn) {
	conn.(*net.TCPConn).SetKeepAlive(true)
	s.tcpIn <- s.NewRedirectTCP(conn)
}

func parseAddr(addr string) (net.IP, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}

	ip := net.ParseIP(host)
	return ip, port, nil
}

func (s *Direct) NewRedirectTCP(conn net.Conn) *context.ConnContext {
	meta := s.cacheMeta

	meta.NetWork = C.TCP
	meta.Inbound = C.Name

	if ip, port, err := parseAddr(conn.RemoteAddr().String()); err == nil {
		meta.SrcIP = ip
		meta.SrcPort = port
	}
	return context.NewConnContext(conn, &meta)
}

func (s *Direct) handleUDP(pc net.PacketConn, buf []byte, addr net.Addr) {
	packet := &packet{
		pc:     pc,
		rAddr:  addr,
		bufRef: buf,
	}
	meta := s.cacheMeta
	meta.NetWork = C.UDP

	p := &defaultinbound.PacketAdapter{
		UDPPacket: packet,
		Meta:      &meta,
	}
	select {
	case s.udpIn <- p:
	default:
	}
}

func (s *Direct) run() error {
	tcpListener, err := NewTCP(s.addr, s.handleTCP)
	if err != nil {
		return err
	}
	log.Infoln("Direct OtherInbound %s listening at: %s", s.Base.inboundName, tcpListener.Address())

	udpListener, err := NewUDP(s.addr, s.handleUDP)
	if err != nil {
		tcpListener.Close()
		return err
	}

	s.Listener = tcpListener
	s.UDPListener = udpListener

	return nil
}

// Close 关闭监听
func (s *Direct) Close() {
	s.Listener.Close()
	s.UDPListener.Close()
	log.Infoln("Direct OtherInbound %s closed", s.Base.inboundName)
}
