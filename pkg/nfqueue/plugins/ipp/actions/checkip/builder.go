// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package checkip

import (
	"errors"
	"fmt"

	"github.com/luids-io/api/event"
	"github.com/luids-io/api/xlist"
	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/builder"
	"github.com/luids-io/netfilter/pkg/nfqueue/plugins/ipp"
)

// Builder returns a builder function
func Builder() builder.BuildActionFn {
	return func(b *builder.Builder, pname string, def builder.ActionDef) (nfqueue.Action, error) {
		//gets service
		service, err := getService(b, def)
		if err != nil {
			return nil, err
		}
		//gets config
		cfg, err := parseConfig(def)
		if err != nil {
			return nil, err
		}
		cfg.LocalNets = b.LocalNets()
		return NewAction(fmt.Sprintf("%s.%s", pname, def.Name), service, cfg, b.Logger())
	}
}

func getService(b *builder.Builder, def builder.ActionDef) (xlist.Checker, error) {
	if len(def.Services) == 0 {
		return nil, errors.New("services required")
	}
	sname, ok := def.Services["xlist"]
	if !ok {
		return nil, errors.New("'xlist' service is required")
	}
	service, ok := b.APIService(sname)
	if !ok {
		return nil, fmt.Errorf("can't find service '%s'", sname)
	}
	c, ok := service.(xlist.Checker)
	if !ok {
		return nil, fmt.Errorf("service '%s' is not an xlist", sname)
	}
	return c, nil
}

func parseConfig(def builder.ActionDef) (Config, error) {
	var cfg Config
	var err error
	if def.Policy == nil {
		return cfg, err
	}
	if def.Policy.Merge {
		cfg.Merge = true
	}
	if def.Policy.OnError != "" {
		cfg.OnError, err = nfqueue.ToVerdict(def.Policy.OnError)
		if err != nil {
			return cfg, err
		}
	}
	if def.Policy.Positive != nil {
		cfg.Positive, err = toRule(*def.Policy.Positive)
		if err != nil {
			return cfg, err
		}
	}
	if def.Policy.Negative != nil {
		cfg.Negative, err = toRule(*def.Policy.Negative)
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

const (
	// ActionClass defines action name
	ActionClass = "checkip"
)

func init() {
	builder.RegisterActionBuilder(ipp.PluginClass, ActionClass, Builder())
}
