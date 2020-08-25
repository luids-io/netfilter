// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/luids-io/core/serverd"
	"github.com/luids-io/netfilter/cmd/lunfqueue/config"
)

//Variables for version output
var (
	Program  = "lunfqueue"
	Build    = "unknown"
	Version  = "unknown"
	Revision = "unknown"
)

var (
	cfg        = config.Default(Program)
	configFile = ""
	version    = false
	help       = false
	debug      = false
	dryRun     = false
)

func init() {
	//config mapped params
	cfg.PFlags()
	//behaviour params
	pflag.StringVar(&configFile, "config", configFile, "Use explicit config file.")
	pflag.BoolVar(&version, "version", version, "Show version.")
	pflag.BoolVarP(&help, "help", "h", help, "Show this help.")
	pflag.BoolVar(&debug, "debug", debug, "Enable debug.")
	pflag.BoolVar(&dryRun, "dry-run", dryRun, "Checks and construct list but not start service.")
	pflag.Parse()
}

func main() {
	if version {
		fmt.Printf("version: %s\nrevision: %s\nbuild: %s\n", Version, Revision, Build)
		os.Exit(0)
	}
	if help {
		pflag.Usage()
		os.Exit(0)
	}

	// load configuration
	err := cfg.LoadIfFile(configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	//creates logger
	logger, err := createLogger(debug)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	// echo version and config
	logger.Infof("%s (version: %s build: %s)", Program, Version, Build)
	if debug {
		logger.Debugf("configuration dump:\n%v", cfg.Dump())
	}

	// creates main server manager
	msrv := serverd.New(Program, serverd.SetLogger(logger))

	// create api services and register
	apisvc, err := createAPIServices(msrv, logger)
	if err != nil {
		logger.Fatalf("couldn't create api registry: %v", err)
	}

	//setup event notifier
	err = setupEventNotify(apisvc, msrv, logger)
	if err != nil {
		logger.Fatalf("couldn't create event notify: %v", err)
	}

	//create packet plugins
	plugins, err := createPacketPlugins(apisvc, msrv, logger)
	if err != nil {
		logger.Fatalf("create builder: %v", err)
	}

	//create nfqueue processor
	pcktproc, err := createNfqueueProc(logger)
	if err != nil {
		logger.Fatalf("create nfqueue processor: %v", err)
	}

	if dryRun {
		fmt.Println("configuration seems ok")
		os.Exit(0)
	}

	//create nfqueue service processor
	pcktsvc, err := createNfqueueSvc(pcktproc, plugins, msrv, logger)
	if err != nil {
		logger.Fatalf("create nfqueue service: %v", err)
	}

	// setup local capture interfaces and register in packet service processor
	err = setupNfqueues(pcktsvc, logger)
	if err != nil {
		logger.Fatalf("registering queues: %v", err)
	}

	// creates health server
	err = createHealthSrv(msrv, logger)
	if err != nil {
		logger.Fatalf("creating health server: %v", err)
	}

	//run server
	err = msrv.Run()
	if err != nil {
		logger.Errorf("running server: %v", err)
	}
	logger.Infof("%s finished", Program)
}
