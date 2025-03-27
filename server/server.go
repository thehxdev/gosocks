package gosocks

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"

	E "github.com/thehxdev/gosocks/errors"
	"github.com/thehxdev/gosocks/internal/bufpool"
	C "github.com/thehxdev/gosocks/internal/constants"
)

const defaultDNSServer string = "8.8.8.8:53"

type AddrRewriterFunc func(dstAddr net.Addr, dstPort uint16) (net.Addr, uint16)
type HandlerFunc func(ctx context.Context, conn net.Conn, connReader *bufio.Reader, req Request) error

type Server struct {
	listener           net.Listener
	logger             *log.Logger
	resolver           *net.Resolver
	rewriter           AddrRewriterFunc
	bpool              bufpool.BufPool
	userConnectHandler HandlerFunc
	// TODO:  userBindHandler      HandlerFunc
	// TODO:  userAssociateHandler HandlerFunc
}

type Request struct {
	version  byte
	command  byte
	destAddr net.Addr
	destPort uint16
}

type Config struct {
	Logger           *log.Logger
	Resolver         *net.Resolver
	Rewriter         AddrRewriterFunc
	ConnectHandler   HandlerFunc
	BindHandler      HandlerFunc
	AssociateHandler HandlerFunc
}

type ReplyParams struct {
	addrType byte
	bndAddr  []byte
	bndPort  uint16
}

var (
	defaultLogger   = log.New(os.Stderr, "[gosocks] ", log.Lshortfile|log.Ldate)
	defaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial("udp", defaultDNSServer)
		},
	}
)

func DialToDestination(conn net.Conn, network string, destAddr net.Addr, destPort uint16) (target net.Conn, err error) {
	address := net.JoinHostPort(destAddr.String(), strconv.Itoa(int(destPort)))
	target, err = net.Dial("tcp", address)
	if err != nil {
		SendReply(conn, E.ErrConnectionRefused, ReplyParams{})
		return
	}
	bnd := target.LocalAddr().(*net.TCPAddr)
	err = SendReply(conn, nil, ReplyParams{
		addrType: C.AddrTypeV4,
		bndAddr:  bnd.IP,
		bndPort:  uint16(bnd.Port),
	})
	return
}

func defaultUserConnectHandler(ctx context.Context, conn net.Conn, connReader *bufio.Reader, req Request) (err error) {
	target, err := DialToDestination(conn, "tcp", req.destAddr, req.destPort)
	defer target.Close()

	targetReader := bufio.NewReader(target)

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, targetReader)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(target, connReader)
		errChan <- err
	}()

	for range 2 {
		select {
		case err = <-errChan:
			if err != nil && err != net.ErrClosed {
				return
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return
}

func New(conf Config) (*Server, error) {
	// TODO: construct the server based on `Config`
	s := &Server{
		logger:   defaultLogger,
		resolver: defaultResolver,
		rewriter: func(destAddr net.Addr, destPort uint16) (net.Addr, uint16) {
			return destAddr, destPort
		},
		bpool:              bufpool.New(C.DefaultMTU),
		userConnectHandler: defaultUserConnectHandler,
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
			err := s.connectionHandler(conn)
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

func (s *Server) readSocks5Request(reader io.Reader, buffer []byte) (r Request, err error) {
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

	addrType := buffer[ptr]
	ptr += 1

	var dstAddrLen int
	switch addrType {
	case C.AddrTypeV4:
		dstAddrLen = 4
		r.destAddr = &net.IPAddr{IP: net.IP(buffer[ptr : ptr+dstAddrLen]).To4()}
	case C.AddrTypeDomainName:
		dstAddrLen = int(buffer[ptr])
		ptr += 1
		host := string(buffer[ptr : ptr+dstAddrLen])
		ips, err := s.resolver.LookupIP(context.Background(), "ip", host)
		if err != nil {
			return r, err
		}
		r.destAddr = &net.IPAddr{IP: ips[0]}
	case C.AddrTypeV6:
		dstAddrLen = 16
		r.destAddr = &net.IPAddr{IP: net.IP(buffer[ptr : ptr+dstAddrLen]).To16()}
	}

	ptr += dstAddrLen
	r.destPort = binary.BigEndian.Uint16(buffer[ptr : ptr+2])

	return
}

func (s *Server) connectionHandler(conn net.Conn) (err error) {
	buf := s.bpool.Get()
	defer s.bpool.Put(buf)

	connReader := bufio.NewReader(conn)

	version, methods, err := readClientMethods(connReader, buf[:cap(buf)])
	if err != nil || version != C.SocksVersion5 {
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

	r, err := s.readSocks5Request(connReader, buf[:cap(buf)])
	// s.logger.Printf("| command: %d | dest address: %v | dest port: %d\n", r.command, r.destAddr, r.destPort)

	r.destAddr, r.destPort = s.rewriter(r.destAddr, r.destPort)
	switch r.command {
	case C.CommandCONNECT:
		err = s.userConnectHandler(context.Background(), conn, connReader, r)
	case C.CommandBIND:
		fallthrough
	case C.CommandASSOCIATE:
		fallthrough
	default:
		err = SendReply(conn, E.ErrCommandNotSupported, ReplyParams{})
	}

	return
}

func SendReply(dest io.Writer, reply E.Error, params ReplyParams) (err error) {
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
	_, err = dest.Write(buf)
	return
}
