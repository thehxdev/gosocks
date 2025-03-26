package gosocks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/thehxdev/gosocks/internal/bufpool"
	C "github.com/thehxdev/gosocks/internal/constants"
	E "github.com/thehxdev/gosocks/internal/errors"
)

type AddrRewriterFunc func(dstAddr []byte, dstPort uint16) ([]byte, uint16)

type Server struct {
	listener net.Listener
	logger   *log.Logger
	dialer   *net.Dialer
	rewriter AddrRewriterFunc
	bpool  bufpool.BufPool
}

type socks5request struct {
	version  byte
	command  byte
	addrType byte
	dstAddr  []byte
	dstPort  uint16
}

type ServerConfig struct {
	Logger *log.Logger
	Dialer *net.Dialer
	Rewriter AddrRewriterFunc
}

type serverReplyParams struct {
	addrType byte
	bndAddr  []byte
	bndPort  uint16
}

var (
	defaultLogger = log.New(os.Stderr, "[gosocks] ", log.Lshortfile|log.Ldate)
	defaultDialer = &net.Dialer{
		Timeout: time.Second * 10,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// google dns as default dns server
				return net.Dial("udp", net.JoinHostPort("8.8.8.8", "53"))
			},
		},
	}
)

func New(conf ServerConfig) (*Server, error) {
	s := &Server{
		logger: defaultLogger,
		dialer: defaultDialer,
		rewriter: func(dstAddr []byte, dstPort uint16) ([]byte, uint16) {
			return dstAddr, dstPort
		},
		bpool: bufpool.New(C.DefaultMTU),
	}
	return s, nil
}

func (s *Server) ListenAndServe(network, addr string) error {
	var err error
	s.listener, err = net.Listen(network, addr)
	if err != nil {
		return err
	}
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// TODO: handle `.Accept()` errors
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			s.logger.Println(err)
		}
		go func() {
			err := s.defaultConnHandler(conn)
			if err != nil {
				s.logger.Println(err)
			}
			conn.Close()
		}()
	}
}

func readClientMethods(reader io.Reader, buffer []byte) (version byte, methods []byte, err error) {
	_, err = reader.Read(buffer)
	if err != nil {
		return
	}

	ptr := 0
	version = buffer[ptr]
	ptr += 1

	nMethods := buffer[ptr]
	ptr += 1

	methods = buffer[ptr:(ptr + int(nMethods))]
	return
}

func readSocks5Request(reader io.Reader, buffer []byte) (r socks5request, err error) {
	_, err = reader.Read(buffer)
	if err != nil {
		return
	}

	ptr := 0
	r.version = buffer[ptr]
	ptr += 1

	r.command = buffer[ptr]
	// skip reserved byte
	ptr += 2

	r.addrType = buffer[ptr]
	ptr += 1

	var dstAddrLen int
	switch r.addrType {
	case C.AddrTypeV4:
		dstAddrLen = 4
		r.dstAddr = buffer[ptr : ptr+dstAddrLen]
	case C.AddrTypeDomainName:
		dstAddrLen = int(buffer[ptr])
		ptr += 1
		r.dstAddr = buffer[ptr : ptr+dstAddrLen]
	case C.AddrTypeV6:
		dstAddrLen = 16
		r.dstAddr = buffer[ptr : ptr+dstAddrLen]
	}

	ptr += dstAddrLen
	r.dstPort = binary.BigEndian.Uint16(buffer[ptr : ptr+2])

	return
}

func (s *Server) defaultConnHandler(conn net.Conn) (err error) {
	buf := s.bpool.Get()
	defer s.bpool.Put(buf)

	socksVersion, methods, err := readClientMethods(conn, buf[:cap(buf)])
	if err != nil || socksVersion != C.SocksVersion5 {
		return
	}

	withUserPass, noAuth := false, false
	for _, m := range methods {
		switch m {
		case C.MethodNoAuth:
			noAuth = true
		case C.MethodUserPass:
			withUserPass = true
		default:
		}
	}

	if withUserPass {
		// TODO: handle user/pass authentication based on RFC1929
		// conn.Write([]byte{ SocksVersion5, MethodUserPass })
	} /* else if noAuth { */
	if noAuth {
		conn.Write([]byte{C.SocksVersion5, C.MethodNoAuth})
	} else {
		conn.Write([]byte{C.SocksVersion5, C.MethodNoAcceptebleMethods})
		return
	}

	r, err := readSocks5Request(conn, buf[:cap(buf)])
	// s.logger.Printf("command: %d | address type: %d | dest addrest: %#v | dest port: %d\n", r.command, r.addrType, r.dstAddr, r.dstPort)

	r.dstAddr, r.dstPort = s.rewriter(r.dstAddr, r.dstPort)
	switch r.command {
	case C.CommandCONNECT:
		err = s.handleCONNECT(conn, r)
	case C.CommandBIND:
		fallthrough
	case C.CommandASSOCIATE:
		fallthrough
	default:
		err = s.sendServerReply(conn, E.ErrCommandNotSupported, serverReplyParams{})
	}

	return
}

func (s *Server) handleCONNECT(conn net.Conn, req socks5request) (err error) {
	var host string

	switch req.addrType {
	case C.AddrTypeV4:
		host = net.IP(req.dstAddr).To4().String()
	case C.AddrTypeV6:
		host = net.IP(req.dstAddr).To16().String()
	case C.AddrTypeDomainName:
		host = string(req.dstAddr)
	default:
		s.sendServerReply(conn, E.ErrAddrTypeNotSupported, serverReplyParams{})
		return
	}

	address := net.JoinHostPort(host, strconv.Itoa(int(req.dstPort)))
	target, err := s.dialer.Dial("tcp", address)
	if err != nil {
		s.sendServerReply(conn, E.ErrConnectionRefused, serverReplyParams{})
		return
	}
	defer target.Close()

	bnd := target.LocalAddr().(*net.TCPAddr)
	s.sendServerReply(conn, nil, serverReplyParams{
		addrType: C.AddrTypeV4,
		bndAddr:  bnd.IP,
		bndPort:  uint16(bnd.Port),
	})

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, target)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(target, conn)
		errChan <- err
	}()

	for range 2 {
		err = <-errChan
		if err != nil && err != net.ErrClosed {
			return
		}
	}

	return
}

func (s *Server) sendServerReply(writer io.Writer, reply E.Error, params serverReplyParams) (err error) {
	var code byte = 0x00
	if reply != nil {
		code = reply.ReplyCode()
	}

	buf := []byte{}
	buf = append(buf, []byte{C.SocksVersion5, code, 0x00, params.addrType}...)

	switch params.addrType {
	case C.AddrTypeV4:
		fallthrough
	case C.AddrTypeV6:
		buf = append(buf, params.bndAddr...)
	case C.AddrTypeDomainName:
		buf = append(buf, byte(len(params.bndAddr)))
		buf = append(buf, params.bndAddr...)
	}

	buf = binary.BigEndian.AppendUint16(buf, params.bndPort)
	_, err = writer.Write(buf)
	return
}
