// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package checkip

import (
	"errors"
	"fmt"

	"github.com/luids-io/api/event"
	"github.com/luids-io/api/xlist"
	"github.com/luids-io/core/option"
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
		service, err := getService(b, def)
		if err != nil {
			return nil, err
		}
		//gets config
		cfg, err := getConfig(b, def)
		if err != nil {
			return nil, err
		}
		return New(aname, service, cfg, b.Logger())
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

func getConfig(b *builder.Builder, def builder.ActionDef) (Config, error) {
	var cfg Config
	var err error
	cfg.LocalNets = b.LocalNets()
	for _, rule := range def.Rules {
		switch rule.When {
		case "listed":
			cfg.WhenListed, err = toRule(rule.Rule)
			if err != nil {
				return cfg, err
			}
		case "unlisted":
			cfg.WhenUnlisted, err = toRule(rule.Rule)
			if err != nil {
				return cfg, err
			}
		}
	}
	if def.OnError != "" {
		cfg.OnError, err = nfqueue.ToVerdict(def.OnError)
		if err != nil {
			return cfg, err
		}
	}
	if def.Opts != nil {
		s, ok, err := option.String(def.Opts, "mode")
		if err != nil {
			return cfg, err
		}
		if ok {
			cfg.Mode, err = toMode(s)
			if err != nil {
				return cfg, err
			}
		}
	}
	return cfg, nil
}

func toRule(def builder.RuleDef) (rule Rule, err error) {
	rule.Merge = def.Merge
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

func toMode(s string) (m Mode, err error) {
	switch s {
	case "", "both":
		m = CheckBoth
	case "src":
		m = CheckSrc
	case "dst":
		m = CheckDst
	default:
		err = fmt.Errorf("invalid mode '%s'", s)
	}
	return
}

func init() {
	builder.RegisterActionBuilder(ipp.PluginClass, ActionClass, Builder())
}
