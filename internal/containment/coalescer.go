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
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/google/agentmesh/api"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SummaryCallback is invoked when a coalescing window closes and duplicate events occurred.
type SummaryCallback func(summary *api.SecuritySignalEvent)

// Coalescer deduplicates repetitive security events within a bounded sliding/tumbling window.
type Coalescer struct {
	window    time.Duration
	onSummary SummaryCallback
	mu        sync.Mutex
	entries   map[string]*coalesceEntry
	closed    bool
}

type coalesceEntry struct {
	key           string
	firstEvent    *api.SecuritySignalEvent
	lastEvent     *api.SecuritySignalEvent
	firstSeenTime time.Time
	lastSeenTime  time.Time
	count         uint32
	timer         *time.Timer
}

// NewCoalescer instantiates a coalescer with the given window duration and summary callback.
func NewCoalescer(window time.Duration, onSummary SummaryCallback) *Coalescer {
	return &Coalescer{
		window:    window,
		onSummary: onSummary,
		entries:   make(map[string]*coalesceEntry),
	}
}

// Record checks whether an incoming event should be coalesced.
// Returns false if this is the first occurrence (must be dispatched immediately).
// Returns true if this event is a duplicate within the active window (suppressed).
func (c *Coalescer) Record(event *api.SecuritySignalEvent) bool {
	if c == nil || c.window <= 0 || event == nil {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return false
	}

	targetService := extractTargetService(event)
	subject := event.Subject
	if subject == "" {
		subject = extractSubject(event)
	}
	key := fmt.Sprintf("%s|%s|%s", event.Type, subject, targetService)

	now := time.Now()
	if event.EventTime != nil {
		now = event.EventTime.AsTime()
	}

	entry, exists := c.entries[key]
	if !exists {
		newEntry := &coalesceEntry{
			key:           key,
			firstEvent:    event,
			lastEvent:     event,
			firstSeenTime: now,
			lastSeenTime:  now,
			count:         0,
		}
		newEntry.timer = time.AfterFunc(c.window, func() {
			c.flushEntry(key)
		})
		c.entries[key] = newEntry
		return false
	}

	entry.count++
	entry.lastEvent = event
	entry.lastSeenTime = now
	return true
}

func (c *Coalescer) flushEntry(key string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	entry, exists := c.entries[key]
	if !exists {
		c.mu.Unlock()
		return
	}
	delete(c.entries, key)
	c.mu.Unlock()

	if entry.count > 0 && c.onSummary != nil {
		summary := c.buildSummaryEvent(entry)
		if summary != nil {
			c.onSummary(summary)
		}
	}
}

func (c *Coalescer) buildSummaryEvent(entry *coalesceEntry) *api.SecuritySignalEvent {
	if entry == nil || entry.lastEvent == nil {
		return nil
	}

	summary := proto.Clone(entry.lastEvent).(*api.SecuritySignalEvent)
	summary.Id = generateUUID()
	summary.EventTime = timestamppb.New(entry.lastSeenTime)

	switch d := summary.Data.(type) {
	case *api.SecuritySignalEvent_TransportRefused:
		if d.TransportRefused != nil {
			d.TransportRefused.CoalescedCount = entry.count
			d.TransportRefused.FirstSeenTime = timestamppb.New(entry.firstSeenTime)
			d.TransportRefused.EventTime = timestamppb.New(entry.lastSeenTime)
		}
	case *api.SecuritySignalEvent_PolicyDenied:
		if d.PolicyDenied != nil {
			d.PolicyDenied.Detail = fmt.Sprintf("%s (coalesced %d occurrences)", d.PolicyDenied.Detail, entry.count)
			d.PolicyDenied.EventTime = timestamppb.New(entry.lastSeenTime)
		}
	case *api.SecuritySignalEvent_IdentityRevoked:
		if d.IdentityRevoked != nil {
			d.IdentityRevoked.Reason = fmt.Sprintf("%s (coalesced %d occurrences)", d.IdentityRevoked.Reason, entry.count)
			d.IdentityRevoked.EventTime = timestamppb.New(entry.lastSeenTime)
		}
	case *api.SecuritySignalEvent_EnrollmentRejected:
		if d.EnrollmentRejected != nil {
			d.EnrollmentRejected.Detail = fmt.Sprintf("%s (coalesced %d occurrences)", d.EnrollmentRejected.Detail, entry.count)
			d.EnrollmentRejected.EventTime = timestamppb.New(entry.lastSeenTime)
		}
	}
	return summary
}

// Close terminates all active timers and flushes any pending summary events.
func (c *Coalescer) Close() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true

	var toFlush []*coalesceEntry
	for _, entry := range c.entries {
		if entry.timer != nil {
			entry.timer.Stop()
		}
		if entry.count > 0 {
			toFlush = append(toFlush, entry)
		}
	}
	c.entries = make(map[string]*coalesceEntry)
	c.mu.Unlock()

	for _, entry := range toFlush {
		if c.onSummary != nil {
			if summary := c.buildSummaryEvent(entry); summary != nil {
				c.onSummary(summary)
			}
		}
	}
}

func extractTargetService(event *api.SecuritySignalEvent) string {
	if event == nil {
		return ""
	}
	switch d := event.Data.(type) {
	case *api.SecuritySignalEvent_PolicyDenied:
		if d.PolicyDenied != nil {
			return d.PolicyDenied.TargetService
		}
	case *api.SecuritySignalEvent_TransportRefused:
		if d.TransportRefused != nil {
			return d.TransportRefused.ProtocolId
		}
	case *api.SecuritySignalEvent_IdentityRevoked:
		if d.IdentityRevoked != nil {
			return d.IdentityRevoked.Source.String()
		}
	case *api.SecuritySignalEvent_EnrollmentRejected:
		if d.EnrollmentRejected != nil {
			return d.EnrollmentRejected.RequestedRole
		}
	}
	return ""
}

func extractSubject(event *api.SecuritySignalEvent) string {
	if event == nil {
		return ""
	}
	switch d := event.Data.(type) {
	case *api.SecuritySignalEvent_PolicyDenied:
		if d.PolicyDenied != nil {
			if d.PolicyDenied.CallerPeerId != "" {
				return d.PolicyDenied.CallerPeerId
			}
			return d.PolicyDenied.CallerSubject
		}
	case *api.SecuritySignalEvent_TransportRefused:
		if d.TransportRefused != nil {
			return d.TransportRefused.PeerId
		}
	case *api.SecuritySignalEvent_IdentityRevoked:
		if d.IdentityRevoked != nil {
			return d.IdentityRevoked.PeerId
		}
	case *api.SecuritySignalEvent_EnrollmentRejected:
		if d.EnrollmentRejected != nil {
			return d.EnrollmentRejected.PeerId
		}
	}
	return ""
}

func generateUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // RFC 4122 version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
