// Copyright 2018 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package ipp

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/luids-io/core/yalogi"
	"github.com/luids-io/netfilter/pkg/nfqueue"
)

// PluginClass registered
const PluginClass = "ipp"

// Config stores configuration for plugin creation
type Config struct {
	Actions []Action
}

// Plugin implementation
type Plugin struct {
	name   string
	logger yalogi.Logger
	//internals
	hrunner *hooksRunner
}

// New returns a new plugin instance
func New(pname string, cfg Config, l yalogi.Logger) (*Plugin, error) {
	p := &Plugin{name: pname, logger: l}
	err := p.init(cfg)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Plugin) init(cfg Config) error {
	//create and register hooks from actions
	hooks := NewHooks()
	for _, action := range cfg.Actions {
		action.Register(hooks)
	}
	p.hrunner = newHooksRunner(hooks)
	return nil
}

// Name implements nfqueue.Plugin interface
func (p *Plugin) Name() string {
	return p.name
}

// Class implements nfqueue.Plugin interface
func (p *Plugin) Class() string {
	return PluginClass
}

// Register implements nfqueue.Plugin interface
func (p *Plugin) Register(hooks *nfqueue.Hooks) {
	//register packets ip4
	hooks.OnPacket(layers.LayerTypeIPv4,
		func(packet gopacket.Packet, ts time.Time) (nfqueue.Verdict, error) {
			ip4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if !ok {
				return nfqueue.Default, fmt.Errorf("%s: can't get ip4 layer", p.name)
			}
			return p.hrunner.PacketIPv4(packet, ip4, ts)
		})
	//register packets ip6
	hooks.OnPacket(layers.LayerTypeIPv6,
		func(packet gopacket.Packet, ts time.Time) (nfqueue.Verdict, error) {
			ip6, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			if !ok {
				return nfqueue.Default, fmt.Errorf("%s: can't get ip4 layer", p.name)
			}
			return p.hrunner.PacketIPv6(packet, ip6, ts)
		})
	//register ticks
	hooks.OnTick(func(lastTick, lastCapture time.Time) error {
		return p.hrunner.Tick(lastTick, lastCapture)
	})
	//register closes
	hooks.OnClose(func() error {
		return p.hrunner.Close()
	})
}

// Layers implements nfqueue.Plugin interface
func (p *Plugin) Layers() []gopacket.LayerType {
	return []gopacket.LayerType{layers.LayerTypeIPv4, layers.LayerTypeIPv6}
}

// CleanUp implements nfqueue.Plugin interface
func (p *Plugin) CleanUp() {}
