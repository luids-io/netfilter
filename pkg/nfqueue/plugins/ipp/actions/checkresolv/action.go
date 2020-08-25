// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package checkresolv

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/luids-io/api/dnsutil"
	"github.com/luids-io/api/dnsutil/parallel"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/luids-io/api/event"
	"github.com/luids-io/core/yalogi"
	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp"
)

// ActionClass defines action name
const ActionClass = "checkresolv"

// Event registered codes
const (
	NetResolvedIP   event.Code = 10012
	NetUnresolvedIP event.Code = 10013
)

// Config stores configuration for action
type Config struct {
	LocalNets []*net.IPNet
	//rules
	WhenResolved   Rule
	WhenUnresolved Rule
	OnError        nfqueue.Verdict
}

// Rule stores information
type Rule struct {
	EventRaise bool
	EventLevel event.Level
	Verdict    nfqueue.Verdict
	Log        bool
}

// Action checks ip addresses against an xlist service
type Action struct {
	name       string
	resolved   Rule
	unresolved Rule
	onError    nfqueue.Verdict
	checkers   []dnsutil.ResolvChecker
	localnets  []*net.IPNet
	logger     yalogi.Logger
}

// New returns a new instance
func New(aname string, checkers []dnsutil.ResolvChecker, cfg Config, l yalogi.Logger) (*Action, error) {
	p := &Action{
		name:       aname,
		resolved:   cfg.WhenResolved,
		unresolved: cfg.WhenUnresolved,
		onError:    cfg.OnError,
		localnets:  cfg.LocalNets,
		checkers:   checkers,
		logger:     l,
	}
	return p, nil
}

// Name implements ipp.Action interface
func (a *Action) Name() string {
	return a.name
}

// Class implements ipp.Action interface
func (a *Action) Class() string {
	return ActionClass
}

// PluginClass implements ipp.Action interface
func (a *Action) PluginClass() string {
	return ipp.PluginClass
}

// Register implements ipp.Action interface
func (a *Action) Register(hooks *ipp.Hooks) {
	a.logger.Debugf("registering hooks %s", a.name)

	hooks.OnPacketIPv4(func(packet gopacket.Packet, ip4 *layers.IPv4, ts time.Time) (nfqueue.Verdict, error) {
		src, dst := ip4.NetworkFlow().Endpoints()
		srcIP := net.IP(src.Raw())
		dstIP := net.IP(dst.Raw())
		if !a.isLocal(srcIP) && a.isLocal(dstIP) {
			return a.doCheck(srcIP, dstIP, dstIP, srcIP)
		}
		if !a.isLocal(dstIP) && a.isLocal(srcIP) {
			return a.doCheck(srcIP, dstIP, srcIP, dstIP)
		}
		return nfqueue.Default, nil
	})

	hooks.OnPacketIPv6(func(packet gopacket.Packet, ip6 *layers.IPv6, ts time.Time) (nfqueue.Verdict, error) {
		src, dst := ip6.NetworkFlow().Endpoints()
		srcIP := net.IP(src.Raw())
		dstIP := net.IP(dst.Raw())
		if !a.isLocal(srcIP) && a.isLocal(dstIP) {
			return a.doCheck(srcIP, dstIP, dstIP, srcIP)
		}
		if !a.isLocal(dstIP) && a.isLocal(srcIP) {
			return a.doCheck(srcIP, dstIP, srcIP, dstIP)
		}
		return nfqueue.Default, nil
	})
}

func (a *Action) doCheck(src, dst, client, server net.IP) (nfqueue.Verdict, error) {
	// check ips in cache
	resp, err := a.checkResolved(client, server)
	if err != nil {
		return a.onError, fmt.Errorf("%s: check %v,%v: %v", a.name, client, server, err)
	}
	// process response and assigns rule
	rule := a.unresolved
	if resp.Result {
		rule = a.resolved
	}
	// do rule
	if rule.Log {
		a.logger.Infof("%s: %v->%v %v %+v", a.name, src, dst, server, resp)
	}
	if rule.EventRaise {
		ecode := NetUnresolvedIP
		if resp.Result {
			ecode = NetResolvedIP
		}
		e := event.New(ecode, rule.EventLevel)
		e.Set("srcip", src.String())
		e.Set("dstip", dst.String())
		e.Set("resolv", server.String())
		if resp.Result {
			e.Set("last", resp.Last.String())
		} else {
			e.Set("store", resp.Store.String())
		}
		event.Notify(e)
	}
	return rule.Verdict, nil
}

func (a *Action) checkResolved(client, server net.IP) (dnsutil.CacheResponse, error) {
	ctx := context.Background()
	// if one checker
	if len(a.checkers) == 1 {
		a.checkers[0].Check(ctx, client, server, "")
	}
	// check in parallel if multiple checkers
	req := parallel.Request{Client: client, Resolved: server}
	responses, hasErr, err := parallel.Check(ctx, a.checkers, []parallel.Request{req})
	if err != nil {
		return dnsutil.CacheResponse{}, err
	}
	if hasErr {
		for _, r := range responses {
			if r.Err != nil {
				return dnsutil.CacheResponse{}, r.Err
			}
		}
	}
	var resp dnsutil.CacheResponse
	for _, r := range responses {
		//get first afirmative response
		if r.Response.Result {
			return r.Response, nil
		}
		//returns last cache time
		if resp.Store.IsZero() {
			resp = r.Response
		} else if r.Response.Store.After(resp.Store) {
			resp = r.Response
		}
	}
	return resp, nil
}

func (a *Action) isLocal(ip net.IP) bool {
	for _, net := range a.localnets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
