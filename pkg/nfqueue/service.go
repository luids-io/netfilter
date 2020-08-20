// Copyright 2019 Luis Guillén Civera <luisguillenc@gmail.com>. View LICENSE.

package nfqueue

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/luids-io/core/yalogi"
)

// PacketService manages multiple nfqueues
type PacketService struct {
	proc    PacketProcessor
	queues  map[int]*queueSource
	plugins []Plugin
	logger  yalogi.Logger
	//control
	wg      sync.WaitGroup
	mu      sync.Mutex
	started bool
	errCh   chan error
}

type options struct {
	logger yalogi.Logger
}

var defaultOptions = options{
	logger: yalogi.LogNull,
}

// Option encapsules options for server
type Option func(*options)

// SetLogger option allows set a custom logger
func SetLogger(l yalogi.Logger) Option {
	return func(o *options) {
		o.logger = l
	}
}

// NewService creates a new Service
func NewService(p PacketProcessor, plugins []Plugin, opt ...Option) *PacketService {
	opts := defaultOptions
	for _, o := range opt {
		o(&opts)
	}
	s := &PacketService{
		logger:  opts.logger,
		proc:    p,
		queues:  make(map[int]*queueSource),
		plugins: plugins,
	}
	return s
}

// Start the service
func (s *PacketService) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return errors.New("service started")
	}
	s.logger.Infof("starting netfilter queue processing service")
	// create errors channel and process it
	s.errCh = make(chan error, ErrorsBuffer)
	go s.procErrs()
	s.started = true
	// start processing all registered sources
	for _, src := range s.queues {
		s.doStart(src)
	}
	return nil
}

// Shutdown the service and stop processing registered packet sources
func (s *PacketService) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return
	}
	s.logger.Infof("shutting down netfilter queue processing service")
	for _, src := range s.queues {
		src.stop()
	}
	s.wg.Wait()
	close(s.errCh)
	s.started = false
}

type queueSource struct {
	qid     int
	started bool
	stop    func()
	errCh   <-chan error
}

// Register packet source with name and start it if service is started
func (s *PacketService) Register(qid int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debugf("registering nfqueue %v", qid)
	_, ok := s.queues[qid]
	if ok {
		return errors.New("queue id exists")
	}
	src := &queueSource{qid: qid}
	s.queues[qid] = src
	if s.started {
		s.doStart(src)
	}
	return nil
}

// Unregister queue by id, stopping if it's started
func (s *PacketService) Unregister(qid int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Debugf("unregistering nfqueue %s", qid)
	src, ok := s.queues[qid]
	if !ok {
		return errors.New("nfqueue doesn't exists")
	}
	if s.started && src.started {
		src.stop()
	}
	delete(s.queues, qid)
	return nil
}

// Ping returns true if errors
func (s *PacketService) Ping() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return errors.New("service not started")
	}
	errs := make([]string, 0, len(s.queues))
	for _, src := range s.queues {
		if !src.started {
			errs = append(errs, strconv.Itoa(src.qid))
		}
	}
	return fmt.Errorf("netfilter queues stopped: %s", strings.Join(errs, ","))
}

//start packet source
func (s *PacketService) doStart(src *queueSource) error {
	s.logger.Infof("starting nfqueue source %v", src.qid)
	sname := fmt.Sprintf("nfqueue(#%v)", src.qid)
	hooks := NewHooks()
	for _, p := range s.plugins {
		p.Register(sname, hooks)
	}
	var err error
	src.stop, src.errCh, err = s.proc.Process(src.qid, hooks)
	if err != nil {
		return err
	}
	src.started = true
	s.wg.Add(1)
	//processing error channel goroutine
	go func(c <-chan error) {
		for n := range c {
			s.errCh <- n
		}
		s.logger.Infof("stopping nfqueue source %v", src.qid)
		src.started = false
		s.wg.Done()
	}(src.errCh)
	return nil
}

//routine for processing error services
func (s *PacketService) procErrs() {
	for err := range s.errCh {
		s.logger.Warnf("%v", err)
	}
}
