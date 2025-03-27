package server

import (
	"bufio"
	"context"
	"io"
	"net"
	"strconv"
	"strings"

	E "github.com/thehxdev/gosocks/errors"
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
	// r and w parameters are reader and writer wrappers for client connection. The reader may be a bufio reader.
	HandleConn(ctx context.Context, r ConnReader, w ConnWriter, req Request) error
}

type defaultConnectHandler struct {
	*net.Dialer
}

// default handler for CONNECT command
func (h *defaultConnectHandler) HandleConn(ctx context.Context, r ConnReader, w ConnWriter, req Request) (err error) {
	address := net.JoinHostPort(req.destAddr.String(), strconv.Itoa(int(req.destPort)))
	target, err := h.Dialer.DialContext(ctx, "tcp", address)
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
	var addrType byte = C.AddrTypeV4
	if strings.Contains(bnd.IP.String(), ":") {
		addrType = C.AddrTypeV6
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
