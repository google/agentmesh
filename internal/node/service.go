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
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"strings"

	"github.com/google/agentmesh/api"
)

// Service is the contract the ServiceRegistry and ingress server use.
// Implementations own all type-specific behaviour; the registry stays
// type-agnostic.
type Service interface {
	Info() *api.ServiceInfo
	Init(ctx context.Context) error
	Handler() http.Handler
	Teardown() error
}

// baseService is the shared embeddable. Holds the fields and default
// Init/Teardown behaviour every service kind needs. backend is typed as
// any because the proto-generated oneof interface is unexported.
type baseService struct {
	info    *api.ServiceInfo
	backend any
	handler http.Handler
	cmd     *exec.Cmd // command backend's ServeHTTP-backing process; nil otherwise
}

// newReverseProxyHandler builds a single-host reverse-proxy handler for a
// URL backend. Same code path as today's URL branch in RegisterService.
func newReverseProxyHandler(targetURL string) (http.Handler, error) {
	p, err := newReverseProxy(targetURL)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// newReverseProxy is newReverseProxyHandler for a service type that hooks
// the backend's responses (ModifyResponse).
func newReverseProxy(targetURL string) (*httputil.ReverseProxy, error) {
	target, err := parseBackendTarget(targetURL)
	if err != nil {
		return nil, err
	}
	u := target.url
	return &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			noTrailingSlash := pr.In.Header.Get(api.HeaderMeshNoTrailingSlash) == "true"
			pr.SetURL(u)
			// The inbound Host is whatever the remote peer sent; the backend
			// is addressed by its configured URL.
			pr.Out.Host = u.Host
			pr.Out.Header.Del(api.HeaderMeshNoTrailingSlash)
			target.apply(pr.Out.Header)
			if noTrailingSlash && !strings.HasSuffix(u.Path, "/") && strings.HasSuffix(pr.Out.URL.Path, "/") {
				pr.Out.URL.Path = strings.TrimSuffix(pr.Out.URL.Path, "/")
			}
			pr.SetXForwarded()
			logger.Debugf("[ReverseProxy] Forwarding to: %q", pr.Out.URL.String())
		},
	}, nil
}

func (b *baseService) Info() *api.ServiceInfo { return b.info }
func (b *baseService) Handler() http.Handler  { return b.handler }

// Init builds the ingress handler for the backend: URL -> reverse-proxy,
// Command -> StdioBridge, one process shared by every caller, with the
// bridge owning the id space and the MCP handshake. Probes and tool
// listings get their own subprocess via MCPService.backendTransport.
// MCPService extends this; it does not replace it.
func (b *baseService) Init(ctx context.Context) error {
	switch x := b.backend.(type) {
	case *api.RegisterServiceRequest_TargetUrl:
		h, err := newReverseProxyHandler(x.TargetUrl)
		if err != nil {
			return err
		}
		b.handler = h
	case *api.RegisterServiceRequest_Command:
		h, cmd, err := createStdioBridgeHandler(x.Command)
		if err != nil {
			return err
		}
		b.handler = h
		b.cmd = cmd
	default:
		return fmt.Errorf("unsupported backend type %T", b.backend)
	}
	return nil
}

// Teardown kills the command backend's process, if any. The bridge's stdout
// reader reaps it, and has already done so for a backend that exited on its
// own, so an already-finished process is not an error.
func (b *baseService) Teardown() error {
	if b.cmd == nil || b.cmd.Process == nil {
		return nil
	}
	if err := b.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func NewServiceFromRequest(req *api.RegisterServiceRequest) (Service, error) {
	info := req.Service
	// Init indexes Command[0] before backendTransport ever runs; reject here so
	// no service type can be constructed in a state that panics on Register.
	if c, ok := req.Backend.(*api.RegisterServiceRequest_Command); ok && len(c.Command.GetCommand()) == 0 {
		return nil, fmt.Errorf("service %q: command backend has no command", info.GetName())
	}
	if err := api.ValidateServiceIngress(info.GetType(), info.GetIngress()); err != nil {
		return nil, fmt.Errorf("service %q: %w", info.GetName(), err)
	}
	if info.GetIngress() != nil && api.EffectiveIngressAuthMode(info.GetIngress()) == api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH {
		if t, ok := req.Backend.(*api.RegisterServiceRequest_TargetUrl); ok {
			bt, err := parseBackendTarget(t.TargetUrl)
			if err != nil {
				return nil, fmt.Errorf("service %q: %w", info.GetName(), err)
			}
			if bt.auth != "" {
				return nil, fmt.Errorf("service %q: ingress auth_mode %q cannot be combined with a backend credential (would expose backend credential without caller authentication)", info.GetName(), api.IngressAuthModeStringPassthrough)
			}
		}
	}
	switch info.Type {
	case api.ServiceType_SERVICE_TYPE_MCP:
		return &MCPService{baseService: baseService{info: info, backend: req.Backend}}, nil
	case api.ServiceType_SERVICE_TYPE_INFERENCE:
		return &InferenceService{baseService: baseService{info: info, backend: req.Backend}}, nil
	case api.ServiceType_SERVICE_TYPE_A2A:
		return &A2AService{baseService: baseService{info: info, backend: req.Backend}}, nil
	case api.ServiceType_SERVICE_TYPE_EGRESS:
		return nil, fmt.Errorf("service %q: egress destinations are assigned by the control plane (PolicyConfig.egress), not registered on a node", info.GetName())
	default:
		return nil, fmt.Errorf("unspecified or unsupported service type: %v", info.Type)
	}
}

// buildRegisterRequest converts a static-config service entry into the
// RegisterServiceRequest the registry consumes.
func buildRegisterRequest(sCfg api.ServiceConfig) (*api.RegisterServiceRequest, error) {
	sType, err := api.ParseServiceType(sCfg.Type)
	if err != nil {
		return nil, fmt.Errorf("invalid service type %q for service %s: %w", sCfg.Type, sCfg.Name, err)
	}
	ing, err := api.ServiceIngressFromConfig(sType, sCfg.Ingress)
	if err != nil {
		return nil, fmt.Errorf("service %s: %w", sCfg.Name, err)
	}
	if ing != nil && api.EffectiveIngressAuthMode(ing) == api.IngressAuthMode_INGRESS_AUTH_MODE_PASSTHROUGH {
		if sCfg.TargetAuthPath != "" {
			return nil, fmt.Errorf("service %s: ingress auth_mode %q cannot be combined with target_auth_path (would expose backend credential without caller authentication)", sCfg.Name, api.IngressAuthModeStringPassthrough)
		}
		if sCfg.TargetURL != "" {
			if bt, pErr := parseBackendTarget(sCfg.TargetURL); pErr == nil && bt.auth != "" {
				return nil, fmt.Errorf("service %s: ingress auth_mode %q cannot be combined with an inline target_url credential (would expose backend credential without caller authentication)", sCfg.Name, api.IngressAuthModeStringPassthrough)
			}
		}
	}
	req := &api.RegisterServiceRequest{
		Service: &api.ServiceInfo{
			Type:        sType,
			Name:        sCfg.Name,
			Description: sCfg.Description,
			Ingress:     ing,
		},
	}
	switch {
	case sCfg.TargetURL != "":
		target := sCfg.TargetURL
		if sCfg.TargetAuthPath != "" {
			var err error
			if target, err = withBackendAuthFile(target, sCfg.TargetAuthPath); err != nil {
				return nil, fmt.Errorf("service %s: %w", sCfg.Name, err)
			}
		}
		req.Backend = &api.RegisterServiceRequest_TargetUrl{TargetUrl: target}
	case len(sCfg.Command) > 0:
		req.Backend = &api.RegisterServiceRequest_Command{
			Command: &api.CommandBackend{
				Command: sCfg.Command,
				Env:     sCfg.Env,
			},
		}
	default:
		return nil, fmt.Errorf("service %s has no backend specified", sCfg.Name)
	}
	return req, nil
}
