package errors

import (
	C "github.com/thehxdev/gosocks/internal/constants"
)

type Error interface {
	error
	ReplyCode() byte
}

type GeneralServerError struct{}

func (e *GeneralServerError) Error() string   { return "" }
func (e *GeneralServerError) ReplyCode() byte { return C.ReplyGeneralServerFailure }

type ConnNotAllowedError struct{}

func (e *ConnNotAllowedError) Error() string   { return "" }
func (e *ConnNotAllowedError) ReplyCode() byte { return C.ReplyConnectionNotAllowed }

type NetworkUnreachableError struct{}

func (e *NetworkUnreachableError) Error() string   { return "" }
func (e *NetworkUnreachableError) ReplyCode() byte { return C.ReplyNetworkUnreachable }

type HostUnreachableError struct{}

func (e *HostUnreachableError) Error() string   { return "" }
func (e *HostUnreachableError) ReplyCode() byte { return C.ReplyHostUnreachable }

type ConnectionRefusedError struct{}

func (e *ConnectionRefusedError) Error() string   { return "" }
func (e *ConnectionRefusedError) ReplyCode() byte { return C.ReplyConnectionRefused }

type TTLExpiredError struct{}

func (e *TTLExpiredError) Error() string   { return "" }
func (e *TTLExpiredError) ReplyCode() byte { return C.ReplyTTLExpired }

type CommandNotSupportedError struct{}

func (e *CommandNotSupportedError) Error() string   { return "" }
func (e *CommandNotSupportedError) ReplyCode() byte { return C.ReplyCommandNotSupported }

type AddressTypeNotSupportedError struct{}

func (e *AddressTypeNotSupportedError) Error() string   { return "" }
func (e *AddressTypeNotSupportedError) ReplyCode() byte { return C.ReplyAddressTypeNotSupported }

var (
	ErrGeneralServerError   = &GeneralServerError{}
	ErrConnNotAllowed       = &ConnNotAllowedError{}
	ErrNetworkUnreachable   = &NetworkUnreachableError{}
	ErrHostUnreachable      = &HostUnreachableError{}
	ErrConnectionRefused    = &ConnectionRefusedError{}
	ErrTTLExpired           = &TTLExpiredError{}
	ErrCommandNotSupported  = &CommandNotSupportedError{}
	ErrAddrTypeNotSupported = &AddressTypeNotSupportedError{}
)
