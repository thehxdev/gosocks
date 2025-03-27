package server

import (
	"io"
	"encoding/binary"

	E "github.com/thehxdev/gosocks/errors"
	C "github.com/thehxdev/gosocks/internal/constants"
)

type ReplyParams struct {
	addrType byte
	bndAddr  []byte
	bndPort  uint16
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
