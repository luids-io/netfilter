// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package config

import (
	"errors"
	"fmt"
	"net"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/luids-io/common/util"
)

// NfqueueCfg defines the configuration of nfqueue manager
type NfqueueCfg struct {
	LocalNets   []string
	PluginDirs  []string
	PluginFiles []string
	QIDs        []int
	Policy      string
	OnError     string
	TickSeconds int
}

// SetPFlags setups posix flags for commandline configuration
func (cfg *NfqueueCfg) SetPFlags(short bool, prefix string) {
	aprefix := ""
	if prefix != "" {
		aprefix = prefix + "."
	}
	pflag.StringSliceVar(&cfg.LocalNets, aprefix+"localnets", cfg.LocalNets, "Local nets.")
	pflag.StringSliceVar(&cfg.PluginDirs, aprefix+"plugin.dirs", cfg.PluginDirs, "Plugin dirs.")
	pflag.StringSliceVar(&cfg.PluginFiles, aprefix+"plugin.files", cfg.PluginFiles, "Plugin files.")
	pflag.IntSliceVar(&cfg.QIDs, aprefix+"qids", cfg.QIDs, "Queue ids to manage.")
	pflag.StringVar(&cfg.Policy, aprefix+"policy", cfg.Policy, "Default policy.")
	pflag.StringVar(&cfg.Policy, aprefix+"onerror", cfg.Policy, "On decoding error verdict.")
	pflag.IntVar(&cfg.TickSeconds, aprefix+"tick", cfg.TickSeconds, "Seconds per tick in packet processors.")
}

// BindViper setups posix flags for commandline configuration and bind to viper
func (cfg *NfqueueCfg) BindViper(v *viper.Viper, prefix string) {
	aprefix := ""
	if prefix != "" {
		aprefix = prefix + "."
	}
	util.BindViper(v, aprefix+"localnets")
	util.BindViper(v, aprefix+"plugin.dirs")
	util.BindViper(v, aprefix+"plugin.files")
	util.BindViper(v, aprefix+"qids")
	util.BindViper(v, aprefix+"policy")
	util.BindViper(v, aprefix+"onerror")
	util.BindViper(v, aprefix+"tick")
}

// FromViper fill values from viper
func (cfg *NfqueueCfg) FromViper(v *viper.Viper, prefix string) {
	aprefix := ""
	if prefix != "" {
		aprefix = prefix + "."
	}
	cfg.LocalNets = v.GetStringSlice(aprefix + "localnets")
	cfg.PluginDirs = v.GetStringSlice(aprefix + "plugin.dirs")
	cfg.PluginFiles = v.GetStringSlice(aprefix + "plugin.files")
	cfg.QIDs = v.GetIntSlice(aprefix + "qids")
	cfg.Policy = v.GetString(aprefix + "policy")
	cfg.OnError = v.GetString(aprefix + "onerror")
	cfg.TickSeconds = v.GetInt(aprefix + "tick")
}

// Empty returns true if configuration is empty
func (cfg NfqueueCfg) Empty() bool {
	if len(cfg.PluginDirs) > 0 {
		return false
	}
	if len(cfg.PluginFiles) > 0 {
		return false
	}
	if len(cfg.QIDs) > 0 {
		return false
	}
	if cfg.Policy != "" {
		return false
	}
	if cfg.OnError != "" {
		return false
	}
	return true
}

// Validate checks that configuration is ok
func (cfg NfqueueCfg) Validate() error {
	for _, s := range cfg.LocalNets {
		_, _, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("localnet '%s' not valid", s)
		}
	}
	for _, file := range cfg.PluginFiles {
		if !util.FileExists(file) {
			return fmt.Errorf("plugin file '%s' doesn't exists", file)
		}
	}
	for _, dir := range cfg.PluginDirs {
		if !util.DirExists(dir) {
			return fmt.Errorf("plugin dir '%s' doesn't exists", dir)
		}
	}
	if len(cfg.QIDs) == 0 {
		return fmt.Errorf("qids field required")
	}
	qids := make(map[int]bool, len(cfg.QIDs))
	for _, qid := range cfg.QIDs {
		if qid < 0 {
			return fmt.Errorf("invalid qid %v value", qid)
		}
		_, repeated := qids[qid]
		if repeated {
			return fmt.Errorf("qid %v is repeated", qid)
		}
		qids[qid] = true
	}
	if !util.IsValid(cfg.Policy, []string{"accept", "drop"}) {
		return errors.New("invalid policy value")
	}
	if !util.IsValid(cfg.OnError, []string{"accept", "drop"}) {
		return errors.New("invalid onerror value")
	}
	if cfg.TickSeconds < 0 {
		return errors.New("invalid tick")
	}
	return nil
}

// Dump configuration
func (cfg NfqueueCfg) Dump() string {
	return fmt.Sprintf("%+v", cfg)
}
