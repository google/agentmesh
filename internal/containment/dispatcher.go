// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package containment

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Dispatcher manages asynchronous non-blocking event submission to external runtimes.
type Dispatcher interface {
	// Dispatch enqueues an event for delivery. Never blocks or panics.
	Dispatch(event *api.SecuritySignalEvent)

	// Close gracefully drains pending events up to the context deadline.
	Close(ctx context.Context) error
}

type dispatcher struct {
	cfg       Config
	client    Client
	coalescer *Coalescer
	queue     chan *api.SecuritySignalEvent
	workerWg  sync.WaitGroup
	mu        sync.RWMutex
	closed    bool
}

// NewDispatcher builds and starts a Dispatcher with bounded queue and worker pool.
func NewDispatcher(cfg Config) (Dispatcher, error) {
	workers := cfg.EffectiveWorkers()
	queueCap := cfg.EffectiveQueueCapacity()

	client, err := NewClient(cfg.Endpoints...)
	if err != nil {
		return nil, fmt.Errorf("containment client initialization failed: %w", err)
	}

	d := &dispatcher{
		cfg:    cfg,
		client: client,
		queue:  make(chan *api.SecuritySignalEvent, queueCap),
	}

	if cfg.CoalescingWindow > 0 {
		d.coalescer = NewCoalescer(cfg.CoalescingWindow, func(summary *api.SecuritySignalEvent) {
			d.enqueueDirect(summary)
		})
	}

	for i := 0; i < workers; i++ {
		d.workerWg.Add(1)
		go d.workerLoop()
	}

	return d, nil
}

// NewDispatcherFromPtr constructs a Dispatcher from a *Config pointer.
func NewDispatcherFromPtr(cfg *Config) (Dispatcher, error) {
	if cfg == nil {
		return NewDispatcher(Config{})
	}
	return NewDispatcher(*cfg)
}

// Dispatch queues an event for out-of-band delivery. Strictly non-blocking.
func (d *dispatcher) Dispatch(event *api.SecuritySignalEvent) {
	if d == nil {
		return
	}
	if event == nil {
		containmentDroppedTotal.WithLabelValues("unknown", "nil_event").Inc()
		return
	}

	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		containmentDroppedTotal.WithLabelValues(event.Type, "dispatcher_closed").Inc()
		return
	}

	if event.Type == "" {
		event.Type = inferSignalType(event)
	}

	// Ensure CloudEvents mandatory attributes
	if event.SpecVersion == "" {
		event.SpecVersion = "1.0"
	}
	if event.Id == "" {
		event.Id = generateUUID()
	}
	if event.EventTime == nil {
		event.EventTime = timestamppb.Now()
	}
	if event.DataContentType == "" {
		event.DataContentType = ContentTypeJSON
	}
	if event.Subject == "" {
		event.Subject = extractSubject(event)
	}

	// Check coalescer
	if d.coalescer != nil && d.coalescer.Record(event) {
		containmentCoalescedTotal.WithLabelValues(event.Type).Inc()
		d.mu.RUnlock()
		return
	}

	if tr := event.GetTransportRefused(); tr != nil && tr.CoalescedCount == 0 {
		tr.CoalescedCount = 1
	}

	// Strictly non-blocking enqueue
	select {
	case d.queue <- event:
		containmentQueuedTotal.WithLabelValues(event.Type).Inc()
		containmentQueueDepth.Set(float64(len(d.queue)))
	default:
		containmentDroppedTotal.WithLabelValues(event.Type, "buffer_full").Inc()
		logger.Warnw("Containment signal queue full; shedding event",
			"type", event.Type,
			"subject", event.Subject,
			"id", event.Id,
			"capacity", cap(d.queue),
			"reason", "buffer_full",
		)
	}
	d.mu.RUnlock()
}

func (d *dispatcher) enqueueDirect(event *api.SecuritySignalEvent) {
	if d == nil || event == nil {
		return
	}

	d.mu.RLock()
	if d.closed {
		d.mu.RUnlock()
		containmentDroppedTotal.WithLabelValues(event.Type, "dispatcher_closed").Inc()
		return
	}

	select {
	case d.queue <- event:
		containmentQueuedTotal.WithLabelValues(event.Type).Inc()
		containmentQueueDepth.Set(float64(len(d.queue)))
	default:
		containmentDroppedTotal.WithLabelValues(event.Type, "buffer_full").Inc()
		logger.Warnw("Containment signal queue full; shedding summary event",
			"type", event.Type,
			"subject", event.Subject,
			"id", event.Id,
			"capacity", cap(d.queue),
			"reason", "buffer_full",
		)
	}
	d.mu.RUnlock()
}

func (d *dispatcher) workerLoop() {
	defer d.workerWg.Done()
	for event := range d.queue {
		containmentQueueDepth.Set(float64(len(d.queue)))
		if d.client != nil {
			_ = d.client.Send(context.Background(), event)
		}
		containmentQueueDepth.Set(float64(len(d.queue)))
	}
}

// Close gracefully stops accepting new events and drains pending events up to ctx deadline.
func (d *dispatcher) Close(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.mu.Unlock()

	if d.coalescer != nil {
		d.coalescer.Close()
	}

	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	close(d.queue)
	d.mu.Unlock()

	drainDone := make(chan struct{})
	go func() {
		d.workerWg.Wait()
		close(drainDone)
	}()

	select {
	case <-drainDone:
		if d.client != nil {
			_ = d.client.Close()
		}
		return nil
	case <-ctx.Done():
		remaining := len(d.queue)
		containmentDroppedTotal.WithLabelValues("all", "shutdown_timeout").Add(float64(remaining))
		logger.Warnw("Containment dispatcher shutdown timed out; remaining events dropped",
			"remaining", remaining,
			"err", ctx.Err(),
		)
		if d.client != nil {
			_ = d.client.Close()
		}
		return ctx.Err()
	}
}
