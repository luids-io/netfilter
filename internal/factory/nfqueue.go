// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package factory

import (
	"errors"
	"time"

	"github.com/luids-io/core/yalogi"
	iconfig "github.com/luids-io/netfilter/internal/config"
	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/builder"
)

// NfqueueProc creates a new nfqueue processor
func NfqueueProc(cfg *iconfig.NfqueueCfg, logger yalogi.Logger) (nfqueue.PacketProcessor, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	oerror, err := nfqueue.ToVerdict(cfg.OnError)
	if err != nil || oerror == nfqueue.Default {
		return nil, errors.New("invalid verdict value")
	}
	policy, err := nfqueue.ToVerdict(cfg.Policy)
	if err != nil || policy == nfqueue.Default {
		return nil, errors.New("invalid verdict value")
	}
	tick := time.Duration(cfg.TickSeconds) * time.Second
	nfqcfg := nfqueue.Config{
		Tick:    tick,
		OnError: oerror,
		Policy:  policy,
	}
	return nfqueue.NewProcessor(nfqcfg, logger), nil
}

// NfqueueSvc creates a new packet sniffer service
func NfqueueSvc(proc nfqueue.PacketProcessor, b *builder.Builder, logger yalogi.Logger) (*nfqueue.PacketService, error) {
	return nfqueue.NewService(proc, b.Plugins(), nfqueue.SetLogger(logger)), nil
}
