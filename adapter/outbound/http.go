package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
)

type Http struct {
	*Base
	user      string
	pass      string
	tlsConfig *tls.Config

	proxyMode HttpProxyMode
}

type HttpOption struct {
	BasicOption
	Name           string `proxy:"name" json:"name"`
	Server         string `proxy:"server" json:"server"`
	Port           int    `proxy:"port" json:"port"`
	UserName       string `proxy:"username,omitempty" json:"username,omitempty"`
	Password       string `proxy:"password,omitempty" json:"password,omitempty"`
	TLS            bool   `proxy:"tls,omitempty" json:"tls,omitempty"`
	SNI            string `proxy:"sni,omitempty" json:"sni,omitempty"`
	SkipCertVerify bool   `proxy:"skip-cert-verify,omitempty" json:"skip-cert-verify,omitempty"`

	ProxyMode HttpProxyMode `proxy:"proxy-mode,omitempty" json:"proxy-mode,omitempty"`
}

type HttpProxyMode int

const (
	// Tunnel 隧道模式，常见代理都支持隧道模式  rfc7231#section-4.3.6
	HttpProxyModeTunnel HttpProxyMode = iota

	// AutoIntermediaries 通过嗅探流量自动判断是否启动中间人模式 rfc7230#section-2.3
	HttpProxyModeAutoIntermediaries
)

func (t HttpProxyMode) String() string {
	return [...]string{"tunnel", "auto"}[t]
}

func (t *HttpProxyMode) FromString(kind string) HttpProxyMode {
	return map[string]HttpProxyMode{
		"tunnel": HttpProxyModeTunnel,
		"auto":   HttpProxyModeAutoIntermediaries,
	}[kind]
}

func (t HttpProxyMode) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *HttpProxyMode) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	*t = t.FromString(s)
	return nil
}

// StreamConn implements C.ProxyAdapter
func (h *Http) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	if h.tlsConfig != nil {
		cc := tls.Client(c, h.tlsConfig)
		ctx, cancel := context.WithTimeout(context.Background(), C.DefaultTLSTimeout)
		defer cancel()
		err := cc.HandshakeContext(ctx)
		c = cc
		if err != nil {
			return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
		}
	}

	// 如果是隧道模式
	if h.proxyMode == HttpProxyModeTunnel {
		if err := h.shakeHand(metadata, c); err != nil {
			return nil, err
		}
		return c, nil
	}

	// 如果是自动判断模式
	return h.ProcessGetMode(c, metadata)
}

func (h *Http) ProcessGetMode(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	reader, writer := net.Pipe()

	x := &xConn{
		Conn:        c,
		WriteCloser: writer,
		wait:        make(chan struct{}),
	}

	//go func() {
	// 嗅探流量，判断是否是 HTTP 流量
	isHttp, cachedReader := SniffHTTPFromConn(reader)

	// 请求不是HTTP请求，则使用CONNECT模式 进行握手，握手完成后将用户流量发送到代理服务器
	if !isHttp {
		// defer x.Close()
		if err := h.shakeHand(metadata, c); err != nil {
			// TODO: 可以尝试返回错误提示给用户
			return nil, err
		}
		// 解锁 x 让外部可读
		x.startOutSideRead()

		go func() {
			// 将客户端发来的流持续的复制到代理服务器
			io.Copy(c, cachedReader)
		}()
	} else {
		x.startOutSideRead()

		// 中间人模式下，把用户的流量读成一个新的请求
		req, err := http.ReadRequest(bufio.NewReader(cachedReader))
		if err != nil {
			return nil, err
		}
		// 修改鉴权信息
		req.Header.Del("Proxy-Authorization")
		if h.user != "" && h.pass != "" {
			auth := h.user + ":" + h.pass
			req.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}
		req.URL.Scheme = "http"
		// 发送给代理服务器
		err = req.WriteProxy(c)
		if err != nil {
			return nil, err
		}
	}
	//}()
	return x, nil
}

// xConn 用于中转用户流量
type xConn struct {
	// 存放与代理服务器的原始连接
	net.Conn

	// 外部使用net.pipe()创建一对conn， 把其中一个保存在这里
	io.WriteCloser

	// 等待握手
	wait chan struct{}
}

func (c *xConn) startOutSideRead() {
	close(c.wait)
}

func (c *xConn) Read(b []byte) (int, error) {
	// https 情况下先阻塞，等待握手完成
	<-c.wait
	n, err := c.Conn.Read(b)
	return n, err
}

func (c *xConn) Write(b []byte) (n int, err error) {
	return c.WriteCloser.Write(b)
}

func (c *xConn) Close() error {
	_ = c.Conn.Close()
	_ = c.WriteCloser.Close()
	return nil
}

// DialContext implements C.ProxyAdapter
func (h *Http) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {
	c, err := dialer.DialContext(ctx, "tcp", h.addr, h.Base.DialOptions(opts...)...)
	if err != nil {
		return nil, fmt.Errorf("%s connect error: %w", h.addr, err)
	}
	tcpKeepAlive(c)

	defer safeConnClose(c, err)

	c, err = h.StreamConn(c, metadata)
	if err != nil {
		return nil, err
	}

	return NewConn(c, h), nil
}

func (h *Http) shakeHand(metadata *C.Metadata, rw io.ReadWriter) error {
	addr := metadata.RemoteAddress()
	req := &http.Request{
		Method: http.MethodConnect,
		URL: &url.URL{
			Host: addr,
		},
		Host: addr,
		Header: http.Header{
			"Proxy-Connection": []string{"Keep-Alive"},
		},
	}

	if h.user != "" && h.pass != "" {
		auth := h.user + ":" + h.pass
		req.Header.Add("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}

	if err := req.Write(rw); err != nil {
		return err
	}

	resp, err := http.ReadResponse(bufio.NewReader(rw), req)
	if err != nil {
		return err
	}

	if resp.StatusCode == http.StatusOK {
		return nil
	}

	if resp.StatusCode == http.StatusProxyAuthRequired {
		return errors.New("HTTP need auth")
	}

	if resp.StatusCode == http.StatusMethodNotAllowed {
		return errors.New("CONNECT method not allowed by proxy")
	}

	if resp.StatusCode >= http.StatusInternalServerError {
		return errors.New(resp.Status)
	}

	return fmt.Errorf("can not connect remote err code: %d", resp.StatusCode)
}

func NewHttp(option HttpOption) *Http {
	var tlsConfig *tls.Config
	if option.TLS {
		sni := option.Server
		if option.SNI != "" {
			sni = option.SNI
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: option.SkipCertVerify,
			ServerName:         sni,
		}
	}

	return &Http{
		Base: &Base{
			name:           option.Name,
			addr:           net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:             C.Http,
			iface:          option.Interface,
			rmark:          option.RoutingMark,
			originalConfig: &option,
		},
		user:      option.UserName,
		pass:      option.Password,
		tlsConfig: tlsConfig,
		proxyMode: option.ProxyMode,
	}
}
