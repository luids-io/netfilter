// Copyright 2020 Luis Guillén Civera <luisguillenc@gmail.com>. All rights reserved.

package nfqueue

import (
	"context"
	"fmt"
	"time"

	nfq "github.com/florianl/go-nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/luids-io/core/yalogi"
)

// PacketProcessor attach to a netfilter queue with the qid
type PacketProcessor interface {
	Process(qid int, hooks *Hooks) (stop func(), errs <-chan error, err error)
}

// queueProc implements a go-nfqueue processor
type queueProc struct {
	policy  Verdict
	onError Verdict
	tick    time.Duration
	logger  yalogi.Logger
}

// Config defines configuration for a netfilter queue
type Config struct {
	Policy  Verdict
	OnError Verdict
	Tick    time.Duration
}

// NewProcessor creates a new basic go-nfqueue processor
func NewProcessor(cfg Config, logger yalogi.Logger) PacketProcessor {
	return &queueProc{
		policy:  cfg.Policy,
		onError: cfg.OnError,
		tick:    cfg.Tick,
		logger:  logger,
	}
}

// Process implements Processor
func (p queueProc) Process(qid int, hooks *Hooks) (func(), <-chan error, error) {
	q := &queue{
		qid:     qid,
		policy:  p.policy,
		onError: p.onError,
		logger:  p.logger,
	}
	err := q.init(hooks, p.tick)
	if err != nil {
		return nil, nil, err
	}
	return q.close, q.errorCh, nil
}

// queue wrappes a go-nfqueue
type queue struct {
	logger          yalogi.Logger
	qid             int
	policy, onError Verdict
	hrunner         *hooksRunner
	lastPacket      time.Time

	netlink *nfq.Nfqueue
	stop    context.CancelFunc
	errorCh chan error
	tdoneCh chan struct{}
	closed  bool
}

func (q *queue) init(hooks *Hooks, tick time.Duration) error {
	// open with configuration and hooks
	err := q.doOpen()
	if err != nil {
		return fmt.Errorf("could not open nfqueue %v: %v", q.qid, err)
	}
	//creates error channel and hooks
	q.hrunner = newHooksRunner(hooks)
	q.errorCh = make(chan error, ErrorsBuffer)
	//creates context for cancelation
	ctx := context.Background()
	ctx, q.stop = context.WithCancel(ctx)
	err = q.doRegister(ctx)
	if err != nil {
		return fmt.Errorf("can't register queue %v: %v", q.qid, err)
	}
	// start timer gorutine
	if tick > 0 {
		q.tdoneCh = make(chan struct{})
		go q.doTick(ctx, tick)
	}
	return nil
}

func (q *queue) close() {
	if q.closed {
		return
	}
	q.closed = true
	q.logger.Debugf("closing nfqueue %v", q.qid)
	q.stop()
	// close netlink in a separate goroutine because a bug in netlink close sometimes hangs
	go func() {
		q.logger.Debugf("closing netlink %v", q.qid)
		q.netlink.Close()
		q.logger.Debugf("closed netlink %v", q.qid)
	}()
	// if tick gorutine, then wait it for close
	if q.tdoneCh != nil {
		<-q.tdoneCh
	}
	// clean up
	errs := q.hrunner.Close()
	for _, err := range errs {
		q.errorCh <- fmt.Errorf("on close qid(#%v): %v", q.qid, err)
	}
	close(q.errorCh)
}

func (q *queue) doOpen() error {
	var err error
	q.logger.Debugf("connecting to nfqueue %v", q.qid)
	q.netlink, err = nfq.Open(
		&nfq.Config{
			NfQueue:      uint16(q.qid),
			MaxPacketLen: 0xFFFF,
			MaxQueueLen:  0xFF,
			Copymode:     nfq.NfQnlCopyPacket,
			Logger:       yalogi.NewStandard(q.logger, yalogi.Debug),
		})
	return err
}

func (q *queue) doRegister(ctx context.Context) error {
	q.logger.Debugf("registering hooks in nfqueue %v", q.qid)
	// register callbacks in netlink
	err := q.netlink.Register(ctx, q.dispatch)
	if err != nil {
		q.netlink.Close()
	}
	return err
}

func (q *queue) doTick(ctx context.Context, tick time.Duration) {
	q.logger.Debugf("starting tick in nfqueue %v", q.qid)
	lastTick := time.Now()
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
LOOPTICK:
	for {
		select {
		case <-ticker.C:
			errs := q.hrunner.Tick(lastTick, q.lastPacket)
			for _, err := range errs {
				q.errorCh <- fmt.Errorf("on tick in qid(#%v): %v", q.qid, err)
			}
			lastTick = time.Now()
		case <-ctx.Done():
			break LOOPTICK
		}
	}
	close(q.tdoneCh)
	return
}

// main processing function, satisfices nfq.HookFunc interface
func (q *queue) dispatch(a nfq.Attribute) int {
	// remove this when netlink close bug fixed
	if q.closed {
		return toNfqVerdict(q.policy)
	}
	// get data from queue
	id := *a.PacketID
	q.logger.Debugf("processing packet %v from queue %v", id, q.qid)
	payload := a.Payload
	if payload == nil {
		q.errorCh <- fmt.Errorf("could't get payload for packet id %v from queue %v", id, q.qid)
		q.netlink.SetVerdict(id, toNfqVerdict(q.onError))
		return 0
	}
	// decode network packet
	layer := layers.LayerTypeIPv4
	packet := gopacket.NewPacket(*payload, layer, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	if err := packet.ErrorLayer(); err != nil {
		layer = layers.LayerTypeIPv6
		packet = gopacket.NewPacket(*payload, layer, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		if err := packet.ErrorLayer(); err != nil {
			q.errorCh <- fmt.Errorf("could't convert to packet %v qid(#%v)", id, q.qid)
			q.netlink.SetVerdict(id, toNfqVerdict(q.onError))
			return 0
		}
	}
	ts := time.Now()
	q.lastPacket = ts
	//fmt.Printf("[%d]\t%v\n", id, packet)
	// process packet hooks
	verdict := q.policy
	for _, layerType := range q.hrunner.Layers() {
		layer := packet.Layer(layerType)
		if layer != nil {
			v, errs := q.hrunner.Packet(layerType, packet, ts)
			for _, err := range errs {
				q.errorCh <- NewError(packet, fmt.Errorf("on packet qid(#%v): %v", q.qid, err))
			}
			if v != Default {
				verdict = v
				break
			}
		}
	}
	// set verdict in queue
	q.netlink.SetVerdict(id, toNfqVerdict(verdict))
	return 0
}

func toNfqVerdict(v Verdict) int {
	value := nfq.NfDrop
	if v == Accept {
		value = nfq.NfAccept
	}
	return value
}
