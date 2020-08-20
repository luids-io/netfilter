// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package nfqueue

import (
	"time"

	"github.com/google/gopacket"
)

type (
	//CbPacket defines a callback on packet
	CbPacket func(gopacket.Packet, time.Time) (Verdict, error)
	//CbTick defines callback for tick routines
	CbTick func(time.Time, time.Time) error
	//CbClose defines callback for cleanups
	CbClose func() error
)

// OnPacket stores callbacks by layer
type OnPacket struct {
	Layer    gopacket.LayerType
	Callback CbPacket
}

// Hooks is responsible for packet processor
type Hooks struct {
	layers   []gopacket.LayerType
	onPacket map[gopacket.LayerType][]OnPacket
	sorted   []OnPacket
	onTick   []CbTick
	onClose  []CbClose
}

// NewHooks returns a new hooks collection
func NewHooks() *Hooks {
	return &Hooks{onPacket: make(map[gopacket.LayerType][]OnPacket)}
}

// OnPacket adds a callback function on new packet
func (h *Hooks) OnPacket(layer gopacket.LayerType, fn CbPacket) {
	callbacks, ok := h.onPacket[layer]
	if !ok {
		h.layers = append(h.layers, layer)
		callbacks = make([]OnPacket, 0)
	}
	cb := OnPacket{Layer: layer, Callback: fn}
	callbacks = append(callbacks, cb)
	h.sorted = append(h.sorted, cb)
	h.onPacket[layer] = callbacks
}

// OnTick adds a callback function on each tick
func (h *Hooks) OnTick(fn CbTick) {
	h.onTick = append(h.onTick, fn)
}

// OnClose adds a callback function when closes source
func (h *Hooks) OnClose(fn CbClose) {
	h.onClose = append(h.onClose, fn)
}

// Layers return registered layers
func (h *Hooks) Layers() []gopacket.LayerType {
	ret := make([]gopacket.LayerType, len(h.layers), len(h.layers))
	copy(ret, h.layers)
	return ret
}

// PacketHooksByLayer returns on packet hooks by layer
func (h *Hooks) PacketHooksByLayer(layer gopacket.LayerType) []OnPacket {
	stored, ok := h.onPacket[layer]
	if !ok {
		return []OnPacket{}
	}
	ret := make([]OnPacket, len(stored), len(stored))
	copy(ret, stored)
	return ret
}

// PacketHooks returns on packet hooks in order
func (h *Hooks) PacketHooks() []OnPacket {
	ret := make([]OnPacket, len(h.sorted), len(h.sorted))
	copy(ret, h.sorted)
	return ret
}

// TickHooks returns on tick hooks
func (h *Hooks) TickHooks() []CbTick {
	ret := make([]CbTick, len(h.onTick), len(h.onTick))
	copy(ret, h.onTick)
	return ret
}

// CloseHooks returns on close hooks
func (h *Hooks) CloseHooks() []CbClose {
	ret := make([]CbClose, len(h.onClose), len(h.onClose))
	copy(ret, h.onClose)
	return ret
}

// hooksRunner executes Hooks
type hooksRunner struct {
	layers   []gopacket.LayerType
	onPacket map[gopacket.LayerType][]OnPacket
	onTick   []CbTick
	onClose  []CbClose
}

// NewHooksRunner returns a HooksRunner
func newHooksRunner(h *Hooks) *hooksRunner {
	runner := &hooksRunner{onPacket: make(map[gopacket.LayerType][]OnPacket)}
	runner.layers = h.Layers()
	for _, layer := range runner.layers {
		runner.onPacket[layer] = h.PacketHooksByLayer(layer)
	}
	runner.onTick = h.TickHooks()
	runner.onClose = h.CloseHooks()
	return runner
}

// Packet executes all registered onPacket hooks for the layerType
// passed in a secuencial way. If some of the hooks returns true, then
// the execution stops and returns true.
func (h *hooksRunner) Packet(layer gopacket.LayerType, packet gopacket.Packet, ts time.Time) (Verdict, []error) {
	callbacks, ok := h.onPacket[layer]
	if ok {
		var v Verdict
		errs := make([]error, 0, len(callbacks))
		for _, cb := range callbacks {
			var err error
			v, err = cb.Callback(packet, ts)
			if err != nil {
				errs = append(errs, err)
			}
			if v != Default {
				return v, errs
			}
		}
		return v, errs
	}
	return Default, nil
}

// Tick executes onTick registered hooks. It pass the last timestamp.
func (h *hooksRunner) Tick(lastTick, lastPacket time.Time) []error {
	errs := make([]error, 0, len(h.onTick))
	for _, cb := range h.onTick {
		err := cb(lastTick, lastPacket)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Close executes on close registered hooks.
func (h *hooksRunner) Close() []error {
	errs := make([]error, 0, len(h.onClose))
	for _, cb := range h.onClose {
		err := cb()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// Layers returns layertypes
func (h *hooksRunner) Layers() []gopacket.LayerType {
	return h.layers
}
