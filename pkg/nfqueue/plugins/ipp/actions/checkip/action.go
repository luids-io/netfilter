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

// ActionClass defines action name
const ActionClass = "checkip"

// Event registered codes
const (
	NetListedIP   event.Code = 10010
	NetUnlistedIP event.Code = 10011
)

// Config stores configuration for action
type Config struct {
	Mode      Mode
	LocalNets []*net.IPNet
	//rules
	WhenListed   Rule
	WhenUnlisted Rule
	OnError      nfqueue.Verdict
}

// Rule stores information
type Rule struct {
	Merge      bool
	EventRaise bool
	EventLevel event.Level
	Verdict    nfqueue.Verdict
	Log        bool
}

// Mode sets mode for checking
type Mode int

//Available values
const (
	CheckBoth Mode = iota
	CheckSrc
	CheckDst
)

// Action checks ip addresses against an xlist service
type Action struct {
	name      string
	listed    Rule
	unlisted  Rule
	onError   nfqueue.Verdict
	cmode     Mode
	checker   xlist.Checker
	localnets []*net.IPNet
	logger    yalogi.Logger
}

// New returns a new instance
func New(aname string, c xlist.Checker, cfg Config, l yalogi.Logger) (*Action, error) {
	p := &Action{
		name:      aname,
		listed:    cfg.WhenListed,
		unlisted:  cfg.WhenUnlisted,
		onError:   cfg.OnError,
		cmode:     cfg.Mode,
		localnets: cfg.LocalNets,
		checker:   c,
		logger:    l,
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
	// check ips in xlist
	resp, err := a.checkIPs(src, dst, res)
	if err != nil {
		return a.onError, fmt.Errorf("%s: check %v: %v", a.name, resp.ip, err)
	}
	// process response and assigns rule
	rule := a.unlisted
	if resp.r.Result {
		rule = a.listed
		if rule.Merge {
			rule, err = mergeReason(rule, resp.r.Reason)
			if err != nil {
				return a.onError, fmt.Errorf("%s: check %v: %v", a.name, resp.ip, err)
			}
		}
	}
	// do rule
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
	if (a.cmode == CheckSrc || a.cmode == CheckBoth) && !a.isLocal(src) {
		resp.r, err = a.checker.Check(context.Background(), src.String(), res)
		if resp.r.Result || err != nil {
			resp.ip = src
			return resp, err
		}
	}
	if (a.cmode == CheckDst || a.cmode == CheckBoth) && !a.isLocal(dst) {
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
