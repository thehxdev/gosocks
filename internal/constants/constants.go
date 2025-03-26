package gosocks

const (
	SocksVersion5 byte = 0x05
	Reserved      byte = 0x00
	DefaultMTU    int  = 1500
)

const (
	MethodNoAuth              byte = 0x00
	MethodGSSAPI              byte = 0x01
	MethodUserPass            byte = 0x02
	MethodNoAcceptebleMethods byte = 0xff
)

const (
	CommandCONNECT   byte = 0x01
	CommandBIND      byte = 0x02
	CommandASSOCIATE byte = 0x03
)

const (
	AddrTypeV4         byte = 0x01
	AddrTypeDomainName byte = 0x03
	AddrTypeV6         byte = 0x04
)

const (
	ReplySuccess                 byte = 0x00
	ReplyGeneralServerFailure    byte = 0x01
	ReplyConnectionNotAllowed    byte = 0x02
	ReplyNetworkUnreachable      byte = 0x03
	ReplyHostUnreachable         byte = 0x04
	ReplyConnectionRefused       byte = 0x05
	ReplyTTLExpired              byte = 0x06
	ReplyCommandNotSupported     byte = 0x07
	ReplyAddressTypeNotSupported byte = 0x08
)
