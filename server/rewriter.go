package server

import (
	"net"
)

type AddrRewriterFunc func(dstAddr net.Addr, dstPort uint16) (net.Addr, uint16)

func NoRewrite(destAddr net.Addr, destPort uint16) (net.Addr, uint16) {
	return destAddr, destPort
}
