// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package nfqueue

import (
	"fmt"

	"github.com/google/gopacket"
)

// ErrorsBuffer sets the default size for error channels
var ErrorsBuffer = 20

// ShowPacketInError if a packet digest will be show with the error string
var ShowPacketInError = false

// DumpPacketInError if a packet dump will be show with the error string
var DumpPacketInError = false

// Error is used for packet processing
type Error struct {
	desc string
	err  error
}

// NewError creates a new packet processing error
func NewError(packet gopacket.Packet, err error) *Error {
	desc := ""
	if ShowPacketInError {
		desc = packet.String()
	}
	if DumpPacketInError {
		desc = packet.Dump()
	}
	return &Error{desc: desc, err: err}
}

// Error implements error interface
func (e *Error) Error() string {
	serr := e.err.Error()
	if e.desc != "" {
		return fmt.Sprintf("%s: [%s]", serr, e.desc)
	}
	return serr
}

func (e *Error) String() string {
	return e.Error()
}
