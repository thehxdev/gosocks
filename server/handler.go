package server

import (
	"context"
	"net"
	"strconv"
	"strings"
	"bufio"
	"io"

	E "github.com/thehxdev/gosocks/errors"
	C "github.com/thehxdev/gosocks/internal/constants"
)

// default handler for CONNECT command
func defaultUserConnectHandler(ctx context.Context, conn net.Conn, connReader *bufio.Reader, req Request) (err error) {
	address := net.JoinHostPort(req.destAddr.String(), strconv.Itoa(int(req.destPort)))
	target, err := net.Dial("tcp", address)
	if err != nil {
		SendReply(conn, E.ErrConnectionRefused, ReplyParams{})
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

	err = SendReply(conn, nil, ReplyParams{
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

