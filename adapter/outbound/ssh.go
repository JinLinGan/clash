package outbound

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Dreamacro/clash/component/dialer"
	C "github.com/Dreamacro/clash/constant"
	"github.com/Dreamacro/clash/log"

	"golang.org/x/crypto/ssh"
)

type Ssh struct {
	*Base
	cfg *ssh.ClientConfig
	//client *ssh.Client

	clients    map[string]*ssh.Client
	clientLock sync.RWMutex

	originConfig *SshOption
}

type SshOption struct {
	BasicOption
	Name       string `proxy:"name" json:"name"`
	Server     string `proxy:"server" json:"server"`
	Port       int    `proxy:"port" json:"port"`
	UserName   string `proxy:"username" json:"username,omitempty"`
	Password   string `proxy:"password,omitempty" json:"password,omitempty"`     // 密码
	KeyPath    string `proxy:"key_path,omitempty" json:"key_path,omitempty"`     // 私钥地址
	Passphrase string `proxy:"passphrase,omitempty" json:"passphrase,omitempty"` // 私钥密码
}

// StreamConn implements C.ProxyAdapter
// relay会调用该方法,传入net.Conn,由于该net.Conn每次都是随机,新建的,无法复用ssh.Client
// TODO: 未关闭该client和connection并每次新建,不知道会不会有其它问题
func (s *Ssh) StreamConn(c net.Conn, metadata *C.Metadata) (net.Conn, error) {
	client, err := s.connect(c, "relay")
	if err != nil {
		return nil, err
	}
	cc, err := client.Dial("tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(cc, s), nil
}

func (s *Ssh) DialContext(ctx context.Context, metadata *C.Metadata, opts ...dialer.Option) (_ C.Conn, err error) {

	conn, err := dialer.DialContext(ctx, "tcp", s.addr, opts...)
	if err != nil {
		return nil, err
	}
	client, err := s.connect(conn, "direct")
	if err != nil {
		return nil, err
	}
	c, err := client.Dial("tcp", metadata.RemoteAddress())
	if err != nil {
		return nil, err
	}
	return NewConn(c, s), nil
}

func (s *Ssh) connect(conn net.Conn, key string) (*ssh.Client, error) {
	s.clientLock.RLock()

	if c, ok := s.clients[key]; ok {
		s.clientLock.RUnlock()
		return c, nil
	}
	s.clientLock.RUnlock()

	s.clientLock.Lock()
	defer s.clientLock.Unlock()

	if c, ok := s.clients[key]; ok {
		return c, nil
	}

	log.Warnln("new ssh conn [%s] %s ", key, s.addr)
	c, chans, reqs, err := ssh.NewClientConn(conn, s.addr, s.cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	client := ssh.NewClient(c, chans, reqs)
	s.clients[key] = client

	go func() {
		err = client.Wait()
		c.Close()

		log.Warnln("ssh client wait: %s", err)
		s.clientLock.Lock()
		delete(s.clients, key)
		s.clientLock.Unlock()
	}()
	return client, nil
}

func NewSsh(option SshOption) (*Ssh, error) {
	cfg := &ssh.ClientConfig{
		User:            option.UserName,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Second * 15,
	}

	if option.Password != "" {
		cfg.Auth = append(cfg.Auth, ssh.Password(option.Password))
	}

	if option.KeyPath != "" {
		buffer, err := ioutil.ReadFile(option.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("read from keyPath '%s' failed", option.KeyPath)
		}

		var signer ssh.Signer
		if option.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(buffer, []byte(option.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(buffer)
		}
		if err != nil {
			return nil, err
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}

	return &Ssh{
		Base: &Base{
			name:           option.Name,
			addr:           net.JoinHostPort(option.Server, strconv.Itoa(option.Port)),
			tp:             C.Ssh,
			iface:          option.Interface,
			rmark:          option.RoutingMark,
			originalConfig: &option,
		},
		cfg:     cfg,
		clients: map[string]*ssh.Client{},
	}, nil
}
