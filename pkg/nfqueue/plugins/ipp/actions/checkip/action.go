// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package checkip

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/luids-io/api/event"
	"github.com/luids-io/api/xlist"
	"github.com/luids-io/core/reason"
	"github.com/luids-io/core/yalogi"
	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp"
)

// Event registered codes
const (
	NetListedIP   event.Code = 10010
	NetUnlistedIP event.Code = 10011
)

// Action register hooks to check sni of clienthellos
type Action struct {
	ipp.Action
	name      string
	positive  Rule
	negative  Rule
	onError   nfqueue.Verdict
	merge     bool
	cmode     CheckMode
	checker   xlist.Checker
	localnets []*net.IPNet
	logger    yalogi.Logger
}

// CheckMode sets mode for checking
type CheckMode int

//Available values
const (
	ModeBoth CheckMode = iota
	ModeSrc
	ModeDst
)

// Rule stores information
type Rule struct {
	EventRaise bool
	EventLevel event.Level
	Verdict    nfqueue.Verdict
	Log        bool
}

// Config stores configuration for action
type Config struct {
	Positive  Rule
	Negative  Rule
	Merge     bool
	OnError   nfqueue.Verdict
	Mode      CheckMode
	LocalNets []*net.IPNet
}

// NewAction returns a instance
func NewAction(aname string, c xlist.Checker, cfg Config, l yalogi.Logger) (*Action, error) {
	p := &Action{
		name:      aname,
		positive:  cfg.Positive,
		negative:  cfg.Negative,
		merge:     cfg.Merge,
		onError:   cfg.OnError,
		cmode:     cfg.Mode,
		localnets: cfg.LocalNets,
		checker:   c,
		logger:    l,
	}
	return p, nil
}

// Name implements nfqueue.Plugin interface
func (a *Action) Name() string {
	return a.name
}

// Class implements nfqueue.Plugin interface
func (a *Action) Class() string {
	return ActionClass
}

// PluginClass implements nfqueue.Plugin interface
func (a *Action) PluginClass() string {
	return ipp.PluginClass
}

// RegisterIP adds hooks to ip process
func (a *Action) RegisterIP(hooks *ipp.Hooks) {
	a.logger.Debugf("registering hooks %s", a.name)

	hooks.OnPacketIPv4(func(packet gopacket.Packet, ip4 *layers.IPv4, ts time.Time) (nfqueue.Verdict, error) {
		src, dst := ip4.NetworkFlow().Endpoints()
		srcIP := net.IP(src.Raw())
		dstIP := net.IP(dst.Raw())
		return a.doCheck(srcIP, dstIP, xlist.IPv4)
	})

	hooks.OnPacketIPv6(func(packet gopacket.Packet, ip6 *layers.IPv6, ts time.Time) (nfqueue.Verdict, error) {
		src, dst := ip6.NetworkFlow().Endpoints()
		srcIP := net.IP(src.Raw())
		dstIP := net.IP(dst.Raw())
		return a.doCheck(srcIP, dstIP, xlist.IPv6)
	})
}

func (a *Action) doCheck(src, dst net.IP, res xlist.Resource) (nfqueue.Verdict, error) {
	resp, err := a.checkIPs(src, dst, res)
	if err != nil {
		return a.onError, fmt.Errorf("%s: check %v: %v", a.name, resp.ip, err)
	}
	rule := a.negative
	if resp.r.Result {
		rule = a.positive
		if a.merge {
			rule, err = mergeReason(rule, resp.r.Reason)
			if err != nil {
				return a.onError, fmt.Errorf("%s: check %v: %v", a.name, resp.ip, err)
			}
		}
	}
	if rule.Log {
		a.logger.Infof("%s: %v->%v %v %+v", a.name, src, dst, resp.ip, resp.r)
	}
	if rule.EventRaise {
		ecode := NetListedIP
		if resp.r.Result {
			ecode = NetUnlistedIP
		}
		e := event.New(ecode, rule.EventLevel)
		e.Set("name", resp.ip.String())
		e.Set("reason", reason.Clean(resp.r.Reason))
		e.Set("srcip", src.String())
		e.Set("dstip", dst.String())
		event.Notify(e)
	}
	return rule.Verdict, nil
}

type response struct {
	ip net.IP
	r  xlist.Response
}

func (a *Action) checkIPs(src, dst net.IP, res xlist.Resource) (response, error) {
	var err error
	var resp response
	if (a.cmode == ModeSrc || a.cmode == ModeBoth) && !a.isLocal(src) {
		resp.r, err = a.checker.Check(context.Background(), src.String(), res)
		if resp.r.Result || err != nil {
			resp.ip = src
			return resp, err
		}
	}
	if (a.cmode == ModeDst || a.cmode == ModeBoth) && !a.isLocal(dst) {
		resp.r, err = a.checker.Check(context.Background(), dst.String(), res)
		if resp.r.Result {
			resp.ip = dst
		}
	}
	return resp, err
}

func (a *Action) isLocal(ip net.IP) bool {
	for _, net := range a.localnets {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}

func mergeReason(r Rule, s string) (Rule, error) {
	p, _, err := reason.ExtractPolicy(s)
	if err != nil {
		return r, err
	}
	v, ok := p.Get("verdict")
	if ok {
		r.Verdict, err = nfqueue.ToVerdict(v)
		if err != nil {
			return r, err
		}
	}
	e, ok := p.Get("event")
	if ok {
		r.EventLevel, r.EventRaise, err = event.ToEventLevel(e)
		if err != nil {
			return r, err
		}
	}
	l, ok := p.Get("log")
	if ok {
		if l == "true" {
			r.Log = true
		}
	}
	return r, nil
}
