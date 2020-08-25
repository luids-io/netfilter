// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package checkresolv

import (
	"errors"
	"fmt"

	"github.com/luids-io/api/dnsutil"
	"github.com/luids-io/api/event"
	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/builder"
	"github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp"
)

// Builder returns a builder function
func Builder() builder.BuildActionFn {
	return func(b *builder.Builder, pname string, def builder.ActionDef) (nfqueue.Action, error) {
		// sanity checks
		if def.Name == "" {
			return nil, errors.New("'name' is required")
		}
		aname := fmt.Sprintf("%s.%s", pname, def.Name)
		//gets service
		services, err := getServices(b, def)
		if err != nil {
			return nil, err
		}
		//gets config
		cfg, err := getConfig(b, def)
		if err != nil {
			return nil, err
		}
		return New(aname, services, cfg, b.Logger())
	}
}

func getServices(b *builder.Builder, def builder.ActionDef) ([]dnsutil.ResolvChecker, error) {
	if len(def.Services) == 0 {
		return nil, errors.New("services required")
	}
	checkers := make([]dnsutil.ResolvChecker, 0, len(def.Services))
	for _, name := range def.Services {
		service, ok := b.APIService(name)
		if !ok {
			return nil, fmt.Errorf("can't find service '%s'", name)
		}
		checker, ok := service.(dnsutil.ResolvChecker)
		if !ok {
			return nil, fmt.Errorf("service '%s' is not an dnsutil.ResolvChecker", name)
		}
		checkers = append(checkers, checker)
	}
	return checkers, nil
}

func getConfig(b *builder.Builder, def builder.ActionDef) (Config, error) {
	var cfg Config
	var err error
	cfg.LocalNets = b.LocalNets()
	for _, rule := range def.Rules {
		switch rule.When {
		case "resolved":
			cfg.WhenResolved, err = toRule(rule.Rule)
			if err != nil {
				return cfg, err
			}
		case "unresolved":
			cfg.WhenUnresolved, err = toRule(rule.Rule)
			if err != nil {
				return cfg, err
			}
		default:
			return cfg, fmt.Errorf("unexpected rule when '%s'", rule.When)
		}
	}
	if def.OnError != "" {
		cfg.OnError, err = nfqueue.ToVerdict(def.OnError)
		if err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

func toRule(def builder.RuleDef) (rule Rule, err error) {
	rule.EventLevel, rule.EventRaise, err = event.ToEventLevel(def.Event)
	if err != nil {
		return
	}
	rule.Verdict, err = nfqueue.ToVerdict(def.Verdict)
	if err != nil {
		return
	}
	rule.Log = def.Log
	return
}

func init() {
	builder.RegisterActionBuilder(ipp.PluginClass, ActionClass, Builder())
}
