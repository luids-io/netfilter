// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package ipp

import (
	"errors"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/luids-io/netfilter/pkg/nfqueue"
)

type (
	//CbPacketIPv4 defines a callback on packet
	CbPacketIPv4 func(gopacket.Packet, *layers.IPv4, time.Time) (nfqueue.Verdict, error)
	//CbPacketIPv6 defines a callback on packet
	CbPacketIPv6 func(gopacket.Packet, *layers.IPv6, time.Time) (nfqueue.Verdict, error)
	//CbTick defines callback for tick routines
	CbTick func(time.Time, time.Time) error
	//CbClose defines callback for cleanups
	CbClose func() error
)

// Hooks is responsible for ip packet processing
type Hooks struct {
	onPacketIP4 []CbPacketIPv4
	onPacketIP6 []CbPacketIPv6
	onTick      []CbTick
	onClose     []CbClose
}

// NewHooks returns a new hooks collection
func NewHooks() *Hooks {
	return &Hooks{}
}

// OnPacketIPv4 adds a callback function on new packet
func (h *Hooks) OnPacketIPv4(fn CbPacketIPv4) {
	h.onPacketIP4 = append(h.onPacketIP4, fn)
}

// OnPacketIPv6 adds a callback function on new packet
func (h *Hooks) OnPacketIPv6(fn CbPacketIPv6) {
	h.onPacketIP6 = append(h.onPacketIP6, fn)
}

// OnTick adds a callback function on each tick
func (h *Hooks) OnTick(fn CbTick) {
	h.onTick = append(h.onTick, fn)
}

// OnClose adds a callback function when closes source
func (h *Hooks) OnClose(fn CbClose) {
	h.onClose = append(h.onClose, fn)
}

// hooksRunner executes Hooks
type hooksRunner struct {
	hooks *Hooks
}

// newHooksRunner returns a HooksRunner
func newHooksRunner(h *Hooks) *hooksRunner {
	return &hooksRunner{hooks: h}
}

// PacketIPv4 executes on ipv4
func (h *hooksRunner) PacketIPv4(packet gopacket.Packet, ip4 *layers.IPv4, ts time.Time) (nfqueue.Verdict, error) {
	v := nfqueue.Default
	errs := make([]string, 0, len(h.hooks.onPacketIP4))
	for _, cb := range h.hooks.onPacketIP4 {
		var err error
		v, err = cb(packet, ip4, ts)
		if err != nil {
			errs = append(errs, err.Error())
		}
		if v != nfqueue.Default {
			break
		}
	}
	if len(errs) > 0 {
		return v, errors.New(strings.Join(errs, ";"))
	}
	return v, nil
}

// PacketIPv6 executes on ipv6
func (h *hooksRunner) PacketIPv6(packet gopacket.Packet, ip6 *layers.IPv6, ts time.Time) (nfqueue.Verdict, error) {
	v := nfqueue.Default
	errs := make([]string, 0, len(h.hooks.onPacketIP6))
	for _, cb := range h.hooks.onPacketIP6 {
		var err error
		v, err = cb(packet, ip6, ts)
		if err != nil {
			errs = append(errs, err.Error())
		}
		if v != nfqueue.Default {
			break
		}
	}
	if len(errs) > 0 {
		return v, errors.New(strings.Join(errs, ";"))
	}
	return v, nil
}

// Tick executes onTick registered hooks. It pass the last timestamp.
func (h *hooksRunner) Tick(lastTick, lastPacket time.Time) error {
	errs := make([]string, 0, len(h.hooks.onTick))
	for _, cb := range h.hooks.onTick {
		err := cb(lastTick, lastPacket)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ";"))
	}
	return nil
}

// Close executes on close registered hooks.
func (h *hooksRunner) Close() error {
	errs := make([]string, 0, len(h.hooks.onClose))
	for _, cb := range h.hooks.onClose {
		err := cb()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ";"))
	}
	return nil
}
