// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package config

import (
	cconfig "github.com/luids-io/common/config"
	"github.com/luids-io/core/goconfig"
	iconfig "github.com/luids-io/netfilter/internal/config"
)

// Default returns the default configuration
func Default(program string) *goconfig.Config {
	cfg, err := goconfig.New(program,
		goconfig.Section{
			Name:     "nfqueue",
			Required: true,
			Short:    true,
			Data: &iconfig.NfqueueCfg{
				QIDs:        []int{0},
				Policy:      "accept",
				OnError:     "drop",
				TickSeconds: 5,
			},
		},
		goconfig.Section{
			Name:     "ids.api",
			Required: false,
			Data:     &cconfig.APIServicesCfg{},
		},
		goconfig.Section{
			Name:     "ids.event",
			Required: false,
			Data: &cconfig.EventNotifyCfg{
				Buffer: 100,
			},
		},
		goconfig.Section{
			Name:     "log",
			Required: true,
			Data: &cconfig.LoggerCfg{
				Level: "info",
			},
		},
		goconfig.Section{
			Name:     "health",
			Required: false,
			Data:     &cconfig.HealthCfg{},
		},
	)
	if err != nil {
		panic(err)
	}
	return cfg
}
