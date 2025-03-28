package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	E "github.com/thehxdev/gosocks/errors"
	"github.com/thehxdev/gosocks/internal/bufpool"
	C "github.com/thehxdev/gosocks/internal/constants"
)

// A wrapper around client connection reader
type ConnReader interface {
	io.Reader
}

// A wrapper around client connection writer
type ConnWriter interface {
	io.Writer
}

// This type wraps a handler for client connection
type Handler interface {
	// r and w parameters are reader and writer wrappers for client connection.
	// The reason behind seperation between reader and writer and also not using an
	// `io.ReadWriter` is because the server wrapes the connection reader in `bufio.Reader`
	// and the connection writer stays on touched.
	HandleConn(ctx context.Context, r ConnReader, w ConnWriter, req Request) error
}

type defaultConnectHandler struct {
	*net.Dialer
}

// default handler for CONNECT command
func (h *defaultConnectHandler) HandleConn(ctx context.Context, r ConnReader, w ConnWriter, req Request) (err error) {
	address := net.JoinHostPort(req.destAddr.String(), strconv.Itoa(int(req.destPort)))
	target, err := h.DialContext(ctx, "tcp", address)
	if err != nil {
		SendReply(w, E.ErrConnectionRefused, ReplyParams{})
		return
	}
	defer target.Close()

	bnd := target.LocalAddr().(*net.TCPAddr)

	// FIXME: Is there a better way to check for ipv4 or ipv6?
	// Keep in mind that `.To4` method on `net.IP` type returns *non-nil* in case
	// of an IPv6 that represents an IPv4. So it's not a good way to check IP version.
	// https://stackoverflow.com/questions/22751035/golang-distinguish-ipv4-ipv6
	var addrType byte
	if strings.Contains(bnd.IP.String(), ":") {
		addrType = C.AddrTypeV6
	} else {
		addrType = C.AddrTypeV4
	}

	err = SendReply(w, nil, ReplyParams{
		addrType: addrType,
		bndAddr:  bnd.IP,
		bndPort:  uint16(bnd.Port),
	})
	if err != nil {
		return
	}

	targetReader := bufio.NewReader(target)

	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(w, targetReader)
		errChan <- err
	}()

	go func() {
		_, err := io.Copy(target, r)
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

type defaultAssociateHandler struct {
	*net.Dialer
	bpool bufpool.BufPool
}

func (h *defaultAssociateHandler) HandleConn(ctx context.Context, r ConnReader, w ConnWriter, req Request) (err error) {
	// TODO:  Create a context for handling udp
	_, cancel := context.WithCancel(ctx)
	defer cancel()

	address := net.JoinHostPort(req.destAddr.String(), strconv.Itoa(int(req.destPort)))
	target, err := h.DialContext(ctx, "udp", address)
	if err != nil {
		SendReply(w, E.ErrConnectionRefused, ReplyParams{})
		return
	}
	defer target.Close()

	udpListener, err := net.ListenUDP("udp", nil)
	if err != nil {
		SendReply(w, E.ErrGeneralServerError, ReplyParams{})
		return
	}

	bnd := udpListener.LocalAddr().(*net.UDPAddr)
	err = SendReply(w, nil, ReplyParams{
		// FIXME: set correct address type
		addrType: C.AddrTypeV4,
		bndAddr:  bnd.IP,
		bndPort:  bnd.AddrPort().Port(),
	})
	if err != nil {
		return
	}

	return
}
