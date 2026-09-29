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

package node

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"sync"

	"github.com/google/sam/api"
)

// StdioBridge backs the POST HTTP ingress route for a command-backed service
// (registered via baseService.Init). It is not used for mesh sessions - see
// MCPService.backendTransport, which gives those their own subprocess
// instead of sharing this one.
//
// One backend process serves every authorized caller, so the bridge owns the
// JSON-RPC id space: each request's id is replaced with a bridge-assigned
// one before it reaches the backend and restored on the way out, and a
// response is delivered only to the request it answers. Two callers sending
// the same id can no longer receive each other's replies. There is no
// broadcast (SSE) side: with a shared process, a server-initiated message
// cannot be attributed to a caller, so it is not delivered to any of them.
type StdioBridge struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	// mu guards nextID, calls and closed. It is never held across I/O.
	mu     sync.Mutex
	nextID uint64
	// calls maps a bridge-assigned id to the request waiting on it.
	calls map[uint64]*pendingCall
	// closed is set once the stdout reader has stopped; the backend can no
	// longer answer, so requests are refused instead of hanging.
	closed bool
	// writeMu serializes stdin writes. Separate from mu: a write blocks when
	// the backend is not reading, and the backend may not be reading because
	// it is blocked writing stdout, which only deliver (needing mu) drains.
	writeMu sync.Mutex
}

type pendingCall struct {
	originalID json.RawMessage
	reply      chan []byte
}

func (b *StdioBridge) Start() {
	b.calls = make(map[uint64]*pendingCall)
	go func() {
		scanner := bufio.NewScanner(b.stdout)
		scanner.Buffer(make([]byte, 0, 64<<10), maxRequestBodyBytes)
		for scanner.Scan() {
			b.deliver(scanner.Bytes())
		}

		if err := scanner.Err(); err != nil {
			logger.Errorf("[StdioBridge] backend stdout unreadable, refusing further requests: %v", err)
		} else {
			logger.Warnf("[StdioBridge] backend closed stdout, refusing further requests")
		}

		// Refuse requests and release waiters before reaping: Wait blocks for
		// as long as the killed process takes to die, and callers must not.
		b.mu.Lock()
		b.closed = true
		for id, call := range b.calls {
			close(call.reply)
			delete(b.calls, id)
		}
		b.mu.Unlock()

		if b.cmd != nil && b.cmd.Process != nil {
			_ = b.cmd.Process.Kill()
			// Reap here, the only stdout reader, so Wait cannot race a read on
			// the pipe it closes; skipping it leaves a zombie until the node exits.
			_ = b.cmd.Wait()
		}
	}()
}

// deliver routes one backend line to the call it answers. Lines that carry
// no bridge id (notifications, requests from the backend, non-JSON output)
// have no owner and are dropped.
func (b *StdioBridge) deliver(line []byte) {
	if len(line) == 0 || line[0] != '{' {
		return
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return
	}
	rawID, ok := msg["id"]
	if !ok {
		return
	}
	bridgeID, err := strconv.ParseUint(string(rawID), 10, 64)
	if err != nil {
		return
	}

	b.mu.Lock()
	call, found := b.calls[bridgeID]
	if found {
		delete(b.calls, bridgeID)
	}
	b.mu.Unlock()
	if !found {
		return
	}

	msg["id"] = call.originalID
	restored, err := json.Marshal(msg)
	if err != nil {
		close(call.reply)
		return
	}
	call.reply <- restored
	close(call.reply)
}

func (b *StdioBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		// No GET: the legacy SSE stream broadcast every backend line to every
		// reader, i.e. every caller's tool output to every other caller.
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	defer func() { _ = r.Body.Close() }()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var msg map[string]json.RawMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "Body must be a JSON-RPC message", http.StatusBadRequest)
		return
	}
	originalID, isCall := msg["id"]

	var call *pendingCall
	var toBackend []byte
	if isCall {
		call = &pendingCall{originalID: originalID, reply: make(chan []byte, 1)}
		b.mu.Lock()
		if b.closed {
			b.mu.Unlock()
			http.Error(w, "Backend process is no longer running", http.StatusServiceUnavailable)
			return
		}
		b.nextID++
		bridgeID := b.nextID
		b.calls[bridgeID] = call
		b.mu.Unlock()
		defer func() {
			b.mu.Lock()
			delete(b.calls, bridgeID)
			b.mu.Unlock()
		}()

		msg["id"] = json.RawMessage(strconv.FormatUint(bridgeID, 10))
		toBackend, err = json.Marshal(msg)
		if err != nil {
			http.Error(w, "Failed to encode request", http.StatusInternalServerError)
			return
		}
	} else {
		toBackend = body
	}

	b.mu.Lock()
	isClosed := b.closed
	b.mu.Unlock()
	if isClosed {
		http.Error(w, "Backend process is no longer running", http.StatusServiceUnavailable)
		return
	}
	// If the backend closes between the check and the write, the write
	// fails or lands in a dead pipe; either way the reader's shutdown has
	// closed call.reply and the select below answers 503.
	b.writeMu.Lock()
	_, err = b.stdin.Write(append(toBackend, '\n'))
	b.writeMu.Unlock()
	if err != nil {
		http.Error(w, "Failed to write to process stdin", http.StatusInternalServerError)
		return
	}

	if !isCall {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	select {
	case <-r.Context().Done():
		return
	case line, ok := <-call.reply:
		if !ok {
			http.Error(w, "Backend process exited before answering", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(line)
	}
}

func createStdioBridgeHandler(cmdBackend *api.CommandBackend) (http.Handler, *exec.Cmd, error) {
	cmd := exec.Command(cmdBackend.Command[0], cmdBackend.Command[1:]...)
	cmd.Env = backendEnv(cmdBackend.Env)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	bridge := &StdioBridge{
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	}
	bridge.Start()

	return bridge, cmd, nil
}
