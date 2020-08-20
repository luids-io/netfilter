// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package ipp

import (
	"errors"
	"fmt"

	"github.com/luids-io/netfilter/pkg/nfqueue"
	"github.com/luids-io/netfilter/pkg/nfqueue/builder"
)

// Builder returns a builder function
func Builder() builder.BuildPluginFn {
	return func(b *builder.Builder, def builder.PluginDef) (nfqueue.Plugin, error) {
		if def.Name == "" {
			return nil, errors.New("'name' is required")
		}
		cfg := Config{}
		if len(def.Actions) > 0 {
			cfg.Actions = make([]Action, 0, len(def.Actions))
			for _, actionDef := range def.Actions {
				action, err := b.BuildAction(def.Name, PluginClass, actionDef)
				if err != nil {
					return nil, err
				}
				tlsaction, ok := action.(Action)
				if !ok {
					return nil, fmt.Errorf("building action '%s' in plugin '%s': can't cast to tlsp.Action", actionDef.Name, def.Name)
				}
				cfg.Actions = append(cfg.Actions, tlsaction)
			}
		}
		return NewPlugin(def.Name, cfg, b.Logger())
	}
}

const (
	// PluginClass registered
	PluginClass = "ipp"
)

func init() {
	builder.RegisterPluginBuilder(PluginClass, Builder())
}
