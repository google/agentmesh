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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"sync"
	"time"

	"github.com/google/sam/api"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// commandSessionLimit caps the subprocesses one command-backed MCP service
// runs at once. Every mesh stream now costs a process, so without a bound an
// authorized peer holding streams open could fork the node out of memory.
const commandSessionLimit = 16

var errTooManyCommandSessions = errors.New("too many concurrent sessions to command backend")

// MCPService extends baseService to handle MCP protocol proxying.
type MCPService struct {
	baseService

	toolsMu      sync.Mutex
	cachedTools  []string
	toolsExpires time.Time

	// sessions is the slot pool for command-backend subprocesses. Nil until
	// first use, when it gets commandSessionLimit slots; a preset channel
	// (tests) is kept as is.
	sessionsOnce sync.Once
	sessions     chan struct{}
}

func (m *MCPService) sessionSlots() chan struct{} {
	m.sessionsOnce.Do(func() {
		if m.sessions == nil {
			m.sessions = make(chan struct{}, commandSessionLimit)
		}
	})
	return m.sessions
}

// boundedTransport takes a slot from slots on Connect and gives it back once
// the connection's Close has reaped the child.
type boundedTransport struct {
	mcp.Transport
	slots chan struct{}
}

func (t *boundedTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	select {
	case t.slots <- struct{}{}:
	default:
		return nil, errTooManyCommandSessions
	}
	conn, err := t.Transport.Connect(ctx)
	if err != nil {
		<-t.slots
		return nil, err
	}
	return &boundedConn{Connection: conn, release: sync.OnceFunc(func() { <-t.slots })}, nil
}

type boundedConn struct {
	mcp.Connection
	release func()
}

func (c *boundedConn) Close() error {
	defer c.release()
	return c.Connection.Close()
}

// Probe reports whether the backend actually speaks MCP, by completing an
// initialize against it.
//
// Deliberately weaker than Tools: a backend serving only resources or prompts
// has no tools and is still a working MCP server, so an empty tool list is no
// reason to withhold it. Failing to initialize is — that is a backend which is
// down, or was never an MCP server to begin with.
//
// The result is deliberately not cached. Callers are the registry's advertise
// path, which asks once per service per reprovide, so the cost is negligible;
// caching would make a backend that has just come up wait out the TTL, which
// is the delay this gating exists to avoid.
func (m *MCPService) Probe(ctx context.Context) error {
	transport, err := m.backendTransport()
	if err != nil {
		return err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "sam-node-probe", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return fmt.Errorf("connect to backend of %q: %w", m.info.GetName(), err)
	}
	// Connect completed the initialize, which is the whole question here; a
	// failure to hang up afterwards does not unmake that.
	_ = session.Close()
	return nil
}

// Init initializes the base service.
func (m *MCPService) Init(ctx context.Context) error {
	return m.baseService.Init(ctx)
}

// Teardown chains to baseService.Teardown.
func (m *MCPService) Teardown() error {
	return m.baseService.Teardown()
}

// backendTransport builds a fresh MCP transport to this service's backend.
// Command backends get their own subprocess per call (mcp.CommandTransport),
// not a shared one: the go-sdk client numbers requests from 1 per
// connection, so a shared process risked one session reading another's
// reply. Stdio MCP is single-session by spec, so this mirrors the URL
// case's fresh-transport-per-session shape rather than giving the bridge a
// per-session id space. Cost: a fresh process per call instead of one
// long-lived one, so slow-starting backends pay startup repeatedly.
func (m *MCPService) backendTransport() (mcp.Transport, error) {
	switch x := m.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		target, err := parseBackendTarget(x.TargetUrl)
		if err != nil {
			return nil, err
		}
		return &mcp.StreamableClientTransport{Endpoint: target.url.String(), HTTPClient: target.client()}, nil
	case *api.RegisterServiceRequest_Command:
		if x.Command == nil || len(x.Command.Command) == 0 {
			return nil, fmt.Errorf("missing command for command-backed MCP service %q", m.info.GetName())
		}
		cmd := exec.Command(x.Command.Command[0], x.Command.Command[1:]...)
		cmd.Env = backendEnv(x.Command.Env)
		return &boundedTransport{
			Transport: &mcp.CommandTransport{Command: cmd},
			slots:     m.sessionSlots(),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported backend type %T for MCP service %q", m.backend, m.info.GetName())
	}
}

// Tools lists the backend's tool names (sorted), cached briefly since the
// discovery announcer polls it on every tick.
func (m *MCPService) Tools(ctx context.Context) ([]string, error) {
	m.toolsMu.Lock()
	defer m.toolsMu.Unlock()
	if m.cachedTools != nil && time.Now().Before(m.toolsExpires) {
		return m.cachedTools, nil
	}
	transport, err := m.backendTransport()
	if err != nil {
		return nil, err
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "sam-node-discovery", Version: "0.1.0"}, nil)
	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return nil, fmt.Errorf("connect to backend of %q: %w", m.info.GetName(), err)
	}
	defer func() { _ = session.Close() }()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("list tools of %q: %w", m.info.GetName(), err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, t := range res.Tools {
		if t != nil && t.Name != "" {
			names = append(names, t.Name)
		}
	}
	sort.Strings(names)
	m.cachedTools = names
	m.toolsExpires = time.Now().Add(backendProbeTTL)
	return names, nil
}

// preflightMethodsUnsupportedByPassThrough lists stateless MCP capability
// probes that HandleStreamPassThrough answers locally instead of forwarding.
// It opens a fresh, sessionless backend connection per stream, so it can
// never truthfully answer these on the backend's behalf; rejecting them
// locally lets the client's own documented fallback (e.g. to "initialize")
// run on the same connection, instead of forwarding a call the backend may
// not understand and losing the stream entirely. Add new SEP-introduced
// preflight methods here as they appear; do not add anything else.
var preflightMethodsUnsupportedByPassThrough = map[string]bool{
	// SEP-2575: sent by go-sdk clients (>= v1.7.0) before "initialize".
	// https://github.com/modelcontextprotocol/modelcontextprotocol/pull/2575
	"server/discover": true,
}

// passThroughDrainTimeout bounds how long HandleStreamPassThrough keeps a
// client-facing stream open after the backend leg has ended, waiting for the
// client to finish reading the last response and hang up on its own. See the
// comment on the drain logic in HandleStreamPassThrough for why this wait
// exists at all.
//
// A var, not a const, so a test can shrink it - the countdown only starts
// once the backend leg is done, so shrinking it does not affect an
// in-progress exchange, only how long a stalled client is tolerated for
// after that.
var passThroughDrainTimeout = 5 * time.Second

// HandleStreamPassThrough connects to the backend and proxies JSON-RPC messages.
func (m *MCPService) HandleStreamPassThrough(s network.Stream, reqCtx RequestContext) {
	defer func() {
		if err := s.Close(); err != nil {
			logger.Debugf("[MCPService] Failed to close MCP stream: %v", err)
		}
	}()

	backendTransport, err := m.backendTransport()
	if err != nil {
		logger.Errorf("[MCPService] %s: %v", m.info.Name, err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backendConn, err := backendTransport.Connect(ctx)
	if err != nil {
		logger.Errorf("[MCPService] %s: failed to connect to backend: %v", m.info.Name, err)
		return
	}
	defer func() { _ = backendConn.Close() }()

	clientTransport := NewStreamTransport(s)
	clientConn, err := clientTransport.Connect(ctx)
	if err != nil {
		logger.Errorf("[MCPService] %s: failed to connect to client: %v", m.info.Name, err)
		return
	}

	// Dumb pipe: proxy JSON-RPC messages between client and backend.
	//
	// The two legs are not symmetric on shutdown. A backend answering one
	// request and then hanging up (a clean EOF, typical of a one-shot
	// HTTP-style backend transport) is normal completion, not a failure of
	// the client-facing side of the pipe - but closing s in reaction to it
	// used to tear down both directions immediately (network.Stream.Close
	// implies CancelRead), including the read side and, per that method's
	// own documented contract, without waiting for the response this same
	// goroutine had just handed to Write to actually reach the peer. Close
	// "does not guarantee receipt of the data"; the documented safe sequence
	// is CloseWrite, then wait for the peer to finish reading (or hang up),
	// then Close. That race is the root cause of google/sam#375: the
	// producer's write reports success, but the immediate teardown right
	// behind it can still lose the response in flight, and the consumer
	// sees EOF instead.
	//
	// So the backend leg ending only half-closes our write side to the
	// client (CloseWrite: no more responses are coming, but nothing already
	// in flight is discarded) and stops relaying backend->client; it leaves
	// the read side alone. The client leg - the client itself finishing the
	// read and hanging up, or a genuine transport error - is what triggers
	// the final s.Close() at the top of this function. passThroughDrainTimeout
	// bounds that wait, but only once the backend leg is actually done
	// (backendDone below) - it is not a cap on the whole exchange, or a
	// slow-but-healthy session would be killed mid-flight for no better
	// reason than having taken a while.
	//
	// clientErrc is buffered for 2, not 1: a client write failure below is
	// also a client-leg error (the stream to the client is dead, so there is
	// nothing left to drain for), and with both goroutines able to send, an
	// unlucky interleaving where the main select has already consumed one
	// value could otherwise leave the second sender blocked forever.
	clientErrc := make(chan error, 2)
	backendDone := make(chan struct{})

	go func() {
		defer close(backendDone)
		for {
			msg, err := backendConn.Read(ctx)
			if err != nil {
				logger.Debugf("[MCPService] %s: backend read error: %v", m.info.Name, err)
				if cwErr := s.CloseWrite(); cwErr != nil {
					logger.Debugf("[MCPService] %s: failed to close write side to client: %v", m.info.Name, cwErr)
				}
				return
			}
			if err := clientConn.Write(ctx, msg); err != nil {
				logger.Debugf("[MCPService] %s: client write error: %v", m.info.Name, err)
				clientErrc <- err
				return
			}
		}
	}()

	go func() {
		for {
			msg, err := clientConn.Read(ctx)
			if err != nil {
				logger.Debugf("[MCPService] %s: client read error: %v", m.info.Name, err)
				clientErrc <- err
				return
			}
			if req, ok := msg.(*jsonrpc.Request); ok && preflightMethodsUnsupportedByPassThrough[req.Method] {
				resp := &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: req.Method + " is not supported by this pass-through proxy"}}
				if werr := clientConn.Write(ctx, resp); werr != nil {
					logger.Debugf("[MCPService] %s: failed to reject %s: %v", m.info.Name, req.Method, werr)
					clientErrc <- werr
					return
				}
				continue
			}
			if req, ok := msg.(*jsonrpc.Request); ok && len(reqCtx.TaskRules) > 0 {
				if errResp := m.authorizeMCPRequest(req, reqCtx); errResp != nil {
					if werr := clientConn.Write(ctx, errResp); werr != nil {
						logger.Debugf("[MCPService] %s: failed to write TAR rejection: %v", m.info.Name, werr)
						clientErrc <- werr
						return
					}
					continue
				}
			}
			if err := backendConn.Write(ctx, msg); err != nil {
				logger.Debugf("[MCPService] %s: backend write error: %v", m.info.Name, err)
				clientErrc <- err
				return
			}
		}
	}()

	// No timeout here: the exchange runs for as long as both legs are
	// making progress. Only once the backend leg ends (backendDone) does a
	// bounded wait for the client to also finish begin, below.
	select {
	case <-clientErrc:
		return
	case <-backendDone:
	}

	select {
	case <-clientErrc:
	case <-time.After(passThroughDrainTimeout):
		logger.Debugf("[MCPService] %s: client did not hang up within %v of the backend finishing; closing", m.info.Name, passThroughDrainTimeout)
	}
}

// authorizeMCPRequest evaluates reqCtx.TaskRules against an inbound JSON-RPC
// request on an MCP stream. Returns a JSON-RPC error response when denied, or
// nil when allowed.
func (m *MCPService) authorizeMCPRequest(req *jsonrpc.Request, reqCtx RequestContext) *jsonrpc.Response {
	if !req.IsCall() {
		return nil
	}
	svcName := m.info.GetName()
	switch req.Method {
	case "initialize", "ping", "tools/list":
		if err := api.EvaluateTaskRules(reqCtx.TaskRules, api.TaskRequestContext{
			ServiceType:        "mcp",
			ServiceName:        svcName,
			AllowMCPStreamInit: true,
		}, time.Now()); err != nil {
			logger.Warnf("[MCPService] %s: TAR denied %s from %s: %v", svcName, req.Method, reqCtx.PeerID, err)
			return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeInvalidRequest, Message: fmt.Sprintf("task authorization denied %s: %v", req.Method, err)}}
		}
		return nil
	case "tools/call":
		var params struct {
			Name string `json:"name"`
		}
		if len(req.Params) == 0 || json.Unmarshal(req.Params, &params) != nil || params.Name == "" {
			return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "tools/call requires a non-empty tool name"}}
		}
		if err := api.EvaluateTaskRules(reqCtx.TaskRules, api.TaskRequestContext{
			ServiceType: "mcp",
			ServiceName: svcName,
			MCPTool:     params.Name,
		}, time.Now()); err != nil {
			logger.Warnf("[MCPService] %s: TAR denied tools/call %q from %s: %v", svcName, params.Name, reqCtx.PeerID, err)
			return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeInvalidRequest, Message: fmt.Sprintf("task authorization denied tool %q: %v", params.Name, err)}}
		}
		return nil
	default:
		if err := api.EvaluateTaskRules(reqCtx.TaskRules, api.TaskRequestContext{
			ServiceType: "mcp",
			ServiceName: svcName,
		}, time.Now()); err != nil {
			logger.Warnf("[MCPService] %s: TAR denied %s from %s: %v", svcName, req.Method, reqCtx.PeerID, err)
			return &jsonrpc.Response{ID: req.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeInvalidRequest, Message: fmt.Sprintf("task authorization denied %s: %v", req.Method, err)}}
		}
		return nil
	}
}
