// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package main

import (
	"fmt"

	"github.com/luids-io/api/event"
	cconfig "github.com/luids-io/common/config"
	cfactory "github.com/luids-io/common/factory"
	"github.com/luids-io/core/apiservice"
	"github.com/luids-io/core/serverd"
	"github.com/luids-io/core/yalogi"
	iconfig "github.com/luids-io/netfilter/internal/config"
	ifactory "github.com/luids-io/netfilter/internal/factory"
	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/builder"
)

func createLogger(debug bool) (yalogi.Logger, error) {
	cfgLog := cfg.Data("log").(*cconfig.LoggerCfg)
	return cfactory.Logger(cfgLog, debug)
}

func createHealthSrv(msrv *serverd.Manager, logger yalogi.Logger) error {
	cfgHealth := cfg.Data("health").(*cconfig.HealthCfg)
	if !cfgHealth.Empty() {
		hlis, health, err := cfactory.Health(cfgHealth, msrv, logger)
		if err != nil {
			logger.Fatalf("creating health server: %v", err)
		}
		msrv.Register(serverd.Service{
			Name:     fmt.Sprintf("health.[%s]", cfgHealth.ListenURI),
			Start:    func() error { go health.Serve(hlis); return nil },
			Shutdown: func() { health.Close() },
		})
	}
	return nil
}

func createAPIServices(msrv *serverd.Manager, logger yalogi.Logger) (apiservice.Discover, error) {
	cfgServices := cfg.Data("ids.api").(*cconfig.APIServicesCfg)
	registry, err := cfactory.APIAutoloader(cfgServices, logger)
	if err != nil {
		return nil, err
	}
	msrv.Register(serverd.Service{
		Name:     "ids.api",
		Ping:     registry.Ping,
		Shutdown: func() { registry.CloseAll() },
	})
	return registry, nil
}

func setupEventNotify(registry apiservice.Discover, msrv *serverd.Manager, logger yalogi.Logger) error {
	cfgEvent := cfg.Data("ids.event").(*cconfig.EventNotifyCfg)
	if !cfgEvent.Empty() {
		ebuffer, err := cfactory.EventNotifyBuffer(cfgEvent, registry, logger)
		if err != nil {
			return err
		}
		msrv.Register(serverd.Service{
			Name:     "ids.event",
			Shutdown: func() { ebuffer.Close() },
		})
		event.SetBuffer(ebuffer)
	}
	return nil
}

func createPacketPlugins(registry apiservice.Discover, msrv *serverd.Manager, logger yalogi.Logger) (*builder.Builder, error) {
	cfgPacketProc := cfg.Data("nfqueue").(*iconfig.NfqueueCfg)
	b, err := ifactory.PacketProcBuilder(cfgPacketProc, registry, logger)
	if err != nil {
		return nil, err
	}
	err = ifactory.PacketPlugins(cfgPacketProc, b, logger)
	if err != nil {
		return nil, err
	}
	// register packet processor service
	msrv.Register(serverd.Service{
		Name:  "nfqueue.processor",
		Start: b.Start,
		Shutdown: func() {
			b.CleanUp()
			b.Shutdown()
		},
	})
	return b, nil
}

func createNfqueueProc(logger yalogi.Logger) (nfqueue.PacketProcessor, error) {
	cfgNfqueue := cfg.Data("nfqueue").(*iconfig.NfqueueCfg)
	return ifactory.NfqueueProc(cfgNfqueue, logger)
}

func createNfqueueSvc(proc nfqueue.PacketProcessor, b *builder.Builder, msrv *serverd.Manager, logger yalogi.Logger) (*nfqueue.PacketService, error) {
	nfqueuesvc, err := ifactory.NfqueueSvc(proc, b, logger)
	if err != nil {
		return nil, err
	}
	// register packet processor service
	msrv.Register(serverd.Service{
		Name:     "nfqueue.service",
		Start:    nfqueuesvc.Start,
		Shutdown: nfqueuesvc.Shutdown,
		Ping:     nfqueuesvc.Ping,
	})
	return nfqueuesvc, nil
}

func setupNfqueues(nfsvc *nfqueue.PacketService, logger yalogi.Logger) error {
	cfgNfqueue := cfg.Data("nfqueue").(*iconfig.NfqueueCfg)
	for _, qid := range cfgNfqueue.QIDs {
		nfsvc.Register(qid)
	}
	return nil
}
