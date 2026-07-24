package ja3

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
)

type contextKey struct{}

var ContextKey = contextKey{}

func FromContext(ctx context.Context) *Fingerprint {
	if fp, ok := ctx.Value(ContextKey).(*Fingerprint); ok {
		return fp
	}
	return nil
}

func SetContext(r *http.Request, fp *Fingerprint) *http.Request {
	ctx := context.WithValue(r.Context(), ContextKey, fp)
	return r.WithContext(ctx)
}

type ConnInfo struct {
	Fingerprint *Fingerprint
	SNI         string
	RemoteAddr  string
}

type Listener struct {
	net.Listener
	tlsConfig *tls.Config
	onHandshake func(info *ConnInfo)
	connInfo   map[net.Conn]*ConnInfo
	mu         sync.RWMutex
}

func NewListener(inner net.Listener, tlsConfig *tls.Config, onHandshake func(info *ConnInfo)) *Listener {
	return &Listener{
		Listener:    inner,
		tlsConfig:   tlsConfig,
		onHandshake: onHandshake,
		connInfo:    make(map[net.Conn]*ConnInfo),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	rawConn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	peeked := &peekedConn{
		Conn:   rawConn,
		reader: bufio.NewReaderSize(rawConn, 8192),
	}

	buf, err := peeked.reader.Peek(5)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	info := &ConnInfo{
		RemoteAddr: rawConn.RemoteAddr().String(),
	}

	if buf[0] == 0x16 {
		peeked.isTLS = true
		fullBuf, err := peeked.reader.Peek(16384)
		if err == nil {
			fp, fpErr := ParseClientHello(fullBuf)
			if fpErr == nil {
				info.Fingerprint = fp
				info.SNI = fp.SNI
			}
		}
	}

	l.mu.Lock()
	l.connInfo[peeked] = info
	l.mu.Unlock()

	if peeked.isTLS && l.tlsConfig != nil {
		tlsConn := tls.Server(peeked, l.tlsConfig)
		if l.onHandshake != nil {
			l.onHandshake(info)
		}
		return &Conn{tlsConn, info.Fingerprint, info.SNI, info}, nil
	}

	return peeked, nil
}

func (l *Listener) GetInfo(conn net.Conn) *ConnInfo {
	l.mu.RLock()
	defer l.mu.RUnlock()
	switch c := conn.(type) {
	case *Conn:
		return c.info
	case *peekedConn:
		return l.connInfo[c]
	}
	return nil
}

type peekedConn struct {
	net.Conn
	reader *bufio.Reader
	isTLS  bool
}

func (c *peekedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

type Conn struct {
	*tls.Conn
	Fingerprint *Fingerprint
	SNI         string
	info        *ConnInfo
}

func (c *Conn) JA3Hash() string {
	if c.info != nil && c.info.Fingerprint != nil {
		return c.info.Fingerprint.JA3Hash
	}
	return ""
}

func (c *Conn) JA3() string {
	if c.info != nil && c.info.Fingerprint != nil {
		return c.info.Fingerprint.JA3
	}
	return ""
}

var _ net.Listener = (*Listener)(nil)
var _ io.Reader = (*peekedConn)(nil)
