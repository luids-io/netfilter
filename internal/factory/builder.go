// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package factory

import (
	"fmt"

	"github.com/luids-io/core/yalogi"

	"github.com/luids-io/common/util"
	"github.com/luids-io/core/apiservice"
	iconfig "github.com/luids-io/netfilter/internal/config"
	"github.com/luids-io/netfilter/pkg/nfqueue/builder"
)

// PacketProcBuilder factory
func PacketProcBuilder(cfg *iconfig.NfqueueCfg, regsvc apiservice.Discover, logger yalogi.Logger) (*builder.Builder, error) {
	err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	//create the builder
	b := builder.New(regsvc, builder.SetLogger(logger))
	//set localnets
	for _, lnet := range cfg.LocalNets {
		b.AddLocalNet(lnet)
	}
	return b, nil
}

// PacketPlugins creates plugins using builder
func PacketPlugins(cfg *iconfig.NfqueueCfg, b *builder.Builder, logger yalogi.Logger) error {
	err := cfg.Validate()
	if err != nil {
		return err
	}
	err = buildPlugins(b, cfg, logger)
	if err != nil {
		return err
	}
	return nil
}

func buildPlugins(b *builder.Builder, cfg *iconfig.NfqueueCfg, logger yalogi.Logger) error {
	dbfiles, err := util.GetFilesDB("json", cfg.PluginFiles, cfg.PluginDirs)
	if err != nil {
		return fmt.Errorf("loading plugins: %v", err)
	}
	actionDefs, err := loadPluginDefs(dbfiles)
	if err != nil {
		return fmt.Errorf("loading plugin defintions: %v", err)
	}
	for _, def := range actionDefs {
		if def.Disabled {
			logger.Debugf("'%s' is disabled", def.Name)
			continue
		}
		logger.Debugf("constructing '%s'", def.Name)
		_, err := b.BuildPlugin(def)
		if err != nil {
			return fmt.Errorf("creating '%s': %v", def.Name, err)
		}
	}
	return nil
}

func loadPluginDefs(dbFiles []string) ([]builder.PluginDef, error) {
	loadedDB := make([]builder.PluginDef, 0)
	for _, file := range dbFiles {
		entries, err := builder.PluginDefsFromFile(file)
		if err != nil {
			return nil, fmt.Errorf("couln't load database: %v", err)
		}
		loadedDB = append(loadedDB, entries...)
	}
	return loadedDB, nil
}
