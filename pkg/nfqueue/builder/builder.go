// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package builder

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"github.com/luids-io/core/apiservice"
	"github.com/luids-io/core/yalogi"
	"github.com/luids-io/netfilter/pkg/nfqueue"
)

// Builder constructs actions using a definition struct
type Builder struct {
	opts   options
	logger yalogi.Logger

	services   apiservice.Discover
	plugins    map[string]bool
	pluginList []nfqueue.Plugin
	actions    map[string]bool

	localNets []*net.IPNet
	startup   []func() error
	shutdown  []func() error
}

type options struct {
	logger   yalogi.Logger
	dataDir  string
	cacheDir string
}

// SetLogger sets a logger for the component
func SetLogger(l yalogi.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

// DataDir sets data dir
func DataDir(s string) Option {
	return func(o *options) {
		o.dataDir = s
	}
}

// CacheDir sets source dir
func CacheDir(s string) Option {
	return func(o *options) {
		o.cacheDir = s
	}
}

var defaultOpts = options{logger: yalogi.LogNull}

// Option is used for builder configuration
type Option func(*options)

// BuildPluginFn defines a function that constructs a plugin
type BuildPluginFn func(b *Builder, def PluginDef) (nfqueue.Plugin, error)

// BuildActionFn defines a function that constructs an action using a definition
type BuildActionFn func(b *Builder, pname string, def ActionDef) (nfqueue.Action, error)

// New creates a new builder
func New(services apiservice.Discover, opt ...Option) *Builder {
	opts := defaultOpts
	for _, o := range opt {
		o(&opts)
	}
	return &Builder{
		opts:     opts,
		logger:   opts.logger,
		services: services,

		plugins:    make(map[string]bool),
		pluginList: make([]nfqueue.Plugin, 0),
		actions:    make(map[string]bool),

		localNets: make([]*net.IPNet, 0),
		startup:   make([]func() error, 0),
		shutdown:  make([]func() error, 0),
	}
}

// AddLocalNet add a local net to builder
func (b *Builder) AddLocalNet(s string) error {
	_, ipvNet, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("adding localnet '%s': %v", s, err)
	}
	b.localNets = append(b.localNets, ipvNet)
	return nil
}

// BuildPlugin creates a plugin using the metadata passed as param
func (b *Builder) BuildPlugin(def PluginDef) (nfqueue.Plugin, error) {
	b.logger.Debugf("building '%s' class '%s'", def.Name, def.Class)
	if def.Name == "" {
		return nil, errors.New("name field is required")
	}
	//check if exists
	_, ok := b.plugins[def.Name]
	if ok {
		return nil, fmt.Errorf("'%s' exists", def.Name)
	}
	//check if disabled
	if def.Disabled {
		return nil, fmt.Errorf("'%s' is disabled", def.Name)
	}
	//get builder
	customb, ok := registryPluginBuilder[def.Class]
	if !ok {
		return nil, fmt.Errorf("can't find a builder for '%s' in '%s'", def.Class, def.Name)
	}
	n, err := customb(b, def) //builds
	if err != nil {
		return nil, fmt.Errorf("building '%s': %v", def.Name, err)
	}
	//register
	b.plugins[def.Name] = true
	b.pluginList = append(b.pluginList, n)
	return n, nil
}

// BuildAction creates an action using the plugin name, class and metadata passed as param
func (b *Builder) BuildAction(pname, pclass string, def ActionDef) (nfqueue.Action, error) {
	b.logger.Debugf("building '%s' class '%s'", def.Name, def.Class)
	if def.Name == "" {
		return nil, errors.New("name field is required")
	}
	fname := fmt.Sprintf("%s.%s", pname, def.Name)
	fclass := fmt.Sprintf("%s.%s", pclass, def.Class)
	//check if exists
	_, ok := b.actions[fname]
	if ok {
		return nil, errors.New("'%s' exists")
	}
	//check if disabled
	if def.Disabled {
		return nil, fmt.Errorf("'%s' is disabled", fname)
	}
	//get builder
	customb, ok := registryActionBuilder[fclass]
	if !ok {
		return nil, fmt.Errorf("can't find a builder for '%s' in '%s'", fclass, fname)
	}
	n, err := customb(b, pname, def) //builds
	if err != nil {
		return nil, fmt.Errorf("building '%s': %v", fname, err)
	}
	//register
	b.actions[fname] = true
	return n, nil
}

// Logger returns logger
func (b Builder) Logger() yalogi.Logger {
	return b.logger
}

// APIService returns service by name
func (b Builder) APIService(name string) (apiservice.Service, bool) {
	return b.services.GetService(name)
}

// LocalNets return localnets
func (b Builder) LocalNets() []*net.IPNet {
	var c []*net.IPNet
	copy(c, b.localNets)
	return c
}

// DataPath returns path for data
func (b Builder) DataPath(data string) string {
	if path.IsAbs(data) {
		return data
	}
	output := data
	if b.opts.dataDir != "" {
		output = b.opts.dataDir + string(os.PathSeparator) + output
	}
	return output
}

// CachePath returns path for cache
func (b Builder) CachePath(data string) string {
	if path.IsAbs(data) {
		return data
	}
	output := data
	if b.opts.cacheDir != "" {
		output = b.opts.cacheDir + string(os.PathSeparator) + output
	}
	return output
}

// OnStartup registers the functions that will be executed during startup.
func (b *Builder) OnStartup(f func() error) {
	b.startup = append(b.startup, f)
}

// OnShutdown registers the functions that will be executed during shutdown.
func (b *Builder) OnShutdown(f func() error) {
	b.shutdown = append(b.shutdown, f)
}

// Start executes all registered functions.
func (b *Builder) Start() error {
	b.logger.Infof("starting builder registered services")
	var ret error
	for _, f := range b.startup {
		err := f()
		if err != nil {
			return err
		}
	}
	return ret
}

// CleanUp all created plugins
func (b *Builder) CleanUp() {
	b.logger.Infof("clean up plugins")
	for _, p := range b.pluginList {
		p.CleanUp()
	}
}

// Shutdown executes all registered functions.
func (b *Builder) Shutdown() error {
	b.logger.Infof("shutting down builder registered services")
	errs := make([]string, 0, len(b.shutdown))
	for i := len(b.shutdown) - 1; i >= 0; i-- {
		fn := b.shutdown[i]
		err := fn()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, ";"))
	}
	return nil
}

// Plugin returns plugin by name
func (b *Builder) Plugin(name string) (nfqueue.Plugin, bool) {
	for _, p := range b.pluginList {
		if p.Name() == name {
			return p, true
		}
	}
	return nil, false
}

// Plugins returns plugins builded
func (b *Builder) Plugins() []nfqueue.Plugin {
	ret := make([]nfqueue.Plugin, 0, len(b.pluginList))
	for _, p := range b.pluginList {
		ret = append(ret, p)
	}
	return ret
}

// RegisterPluginBuilder registers a plugin builder for class
func RegisterPluginBuilder(class string, builder BuildPluginFn) {
	registryPluginBuilder[class] = builder
}

// RegisterActionBuilder registers an action builder for class
func RegisterActionBuilder(pclass, aclass string, builder BuildActionFn) {
	registryActionBuilder[fmt.Sprintf("%s.%s", pclass, aclass)] = builder
}

var registryPluginBuilder map[string]BuildPluginFn
var registryActionBuilder map[string]BuildActionFn

func init() {
	registryPluginBuilder = make(map[string]BuildPluginFn)
	registryActionBuilder = make(map[string]BuildActionFn)
}
