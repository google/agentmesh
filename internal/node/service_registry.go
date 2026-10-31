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
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/agentmesh/api"
)

// directoryProvider is what ServiceRegistry asks of the directory: to
// announce a key and to withdraw it. Production wires this to the node's
// Directory; tests use a fake.
type directoryProvider interface {
	Provide(ctx context.Context, key []byte, service string) error
	Withdraw(ctx context.Context, key []byte) error
}

type ingressDirectoryProvider interface {
	ProvideWithIngress(ctx context.Context, key []byte, service string, ingress *api.ServiceIngress) error
}

// backendProber is implemented by services that can be asked whether their
// backend is really serving. Services that cannot be asked are advertised
// unconditionally.
type backendProber interface {
	Probe(ctx context.Context) error
}

// defaultDHTProbeTimeout is the default bound on one backend probe before
// advertising, used when a ServiceRegistry isn't given an explicit
// BackendProbeTimeout (see Options.BackendProbeTimeout / --backend-probe-
// timeout). Command-spawned backends (agentmesh-node.yaml's `command`, launched as
// a local subprocess) can need longer than this to answer their first
// request - a moderately-featured interpreted-language MCP server's own
// import/startup cost alone can exceed 2s - so this is a floor, not
// something every backend is expected to meet.
const defaultDHTProbeTimeout = 2 * time.Second

// advertisable reports whether a service is fit to be published to the DHT.
//
// Gossip already withholds announcements for a backend that does not answer,
// but the DHT is the other half of discovery and had no such check, so a
// backend that is not an MCP server at all stayed discoverable as one: it was
// listed by discover_remote_services and only failed later, at initialize, in
// the caller's face. Advertising is a claim the node makes on the backend's
// behalf, so it is the node that should verify it.
func advertisable(ctx context.Context, svc Service, probeTimeout time.Duration) error {
	prober, ok := svc.(backendProber)
	if !ok {
		return nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return prober.Probe(probeCtx)
}

// ServiceRegistry is the type-agnostic owner of registered services.
type ServiceRegistry struct {
	mu       sync.RWMutex
	services map[string]Service
	dht      directoryProvider

	// reprovideNow asks the node to run a reprovide cycle now, so a service
	// registered after the loop last ran does not wait a whole interval to be
	// advertised. Optional; nil outside a running node.
	reprovideNow func()

	// onIngressRegistered is called when an ingress-enabled service is
	// registered so the node can log its public router ingress URLs.
	onIngressRegistered func(info *api.ServiceInfo)

	// backendProbeTimeout bounds each backend probe in advertisable. Set once
	// at construction (see NewServiceRegistry); never mutated afterwards, so
	// reading it needs no lock.
	backendProbeTimeout time.Duration
}

// NewServiceRegistry constructs a registry bounding backend probes by
// backendProbeTimeout. A zero or negative value falls back to
// defaultDHTProbeTimeout, so callers can pass an unset
// Options.BackendProbeTimeout straight through without an explicit
// zero-check.
func NewServiceRegistry(d directoryProvider, backendProbeTimeout time.Duration) *ServiceRegistry {
	if backendProbeTimeout <= 0 {
		backendProbeTimeout = defaultDHTProbeTimeout
	}
	return &ServiceRegistry{
		services:            map[string]Service{},
		dht:                 d,
		backendProbeTimeout: backendProbeTimeout,
	}
}

// Register initialises a service, advertises it on the DHT, and inserts it
// into the map. Init runs before Provide so a failed handler-build never
// briefly advertises an unservable name.
//
// A backend that does not answer is registered but not advertised, rather than
// rejected: backends routinely start after the node does, and the reprovide
// loop picks them up once they answer.
//
// registering a name again replaces the instance and tears the old one down
func (r *ServiceRegistry) Register(ctx context.Context, svc Service) error {
	info := svc.Info()
	if info.Type == api.ServiceType_SERVICE_TYPE_UNSPECIFIED {
		return fmt.Errorf("cannot register service with unspecified type")
	}
	// The same check the config loader runs, for services that arrive by
	// other routes (FFI, tests): a name carrying its own scheme, such as
	// "plugin://x", would be addressed as type://plugin://x and dispatch
	// could no longer tell which type the policy was evaluated on.
	typeStr, err := api.ServiceTypeToString(info.Type)
	if err != nil {
		return err
	}
	if err := api.ValidateServiceFormat(typeStr + "://" + info.Name); err != nil {
		return fmt.Errorf("invalid service name %q: %w", info.Name, err)
	}
	if err := api.ValidateServiceIngress(info.Type, info.GetIngress()); err != nil {
		return fmt.Errorf("service %q: %w", info.Name, err)
	}

	// Policy is evaluated on type://name and the registry is keyed on name,
	// so a second type under the same name would let a grant for one reach
	// the other. One name, one service.
	r.mu.RLock()
	existing, taken := r.services[info.Name]
	r.mu.RUnlock()
	if taken && existing.Info().Type != info.Type {
		return fmt.Errorf("service name %q is already registered as %s; a name cannot serve two types", info.Name, existing.Info().Type)
	}

	if err := svc.Init(ctx); err != nil {
		return fmt.Errorf("init %s: %w", info.Name, err)
	}

	nameKey, err := api.ServiceKey(info.Type, info.Name)
	if err != nil {
		return err
	}
	typeKey, err := api.ServiceKey(info.Type, "")
	if err != nil {
		return err
	}

	probeErr := advertisable(ctx, svc, r.backendProbeTimeout)
	if probeErr != nil {
		logger.Warnf("[ServiceRegistry] Registered %s/%s but not advertising it: backend did not answer: %v", info.Type, info.Name, probeErr)
	} else {
		nameCtx, nameCancel := context.WithTimeout(ctx, 5*time.Second)
		defer nameCancel()
		if err := r.provide(nameCtx, nameKey, serviceTarget(info), info.GetIngress()); err != nil {
			logger.Warnf("[ServiceRegistry] Announcing %s by name: %v", info.Name, err)
		}

		typeCtx, typeCancel := context.WithTimeout(ctx, 5*time.Second)
		defer typeCancel()
		if err := r.provide(typeCtx, typeKey, serviceTarget(info), nil); err != nil {
			logger.Warnf("[ServiceRegistry] Announcing %s by type: %v", info.Name, err)
		}
	}

	r.mu.Lock()
	replaced := r.services[info.Name]
	r.services[info.Name] = svc
	r.mu.Unlock()

	if replaced != nil && replaced != svc {
		if err := replaced.Teardown(); err != nil {
			logger.Errorf("[ServiceRegistry] Teardown replaced %s: %v", info.Name, err)
		}
	}

	if probeErr == nil {
		logger.Infof("[ServiceRegistry] Registered and announced %s/%s", info.Type, info.Name)
		if info.GetIngress() != nil && r.onIngressRegistered != nil {
			r.onIngressRegistered(info)
		}
	} else if r.reprovideNow != nil {
		r.reprovideNow()
	}
	return nil
}

// Unregister removes the service from the map, withdraws its records from
// the directory and calls Teardown. The record by type stays while another
// service of that type is registered. Unknown names are a no-op.
func (r *ServiceRegistry) Unregister(ctx context.Context, name string) error {
	r.mu.Lock()
	svc, ok := r.services[name]
	delete(r.services, name)
	typeStillServed := false
	if ok {
		for _, other := range r.services {
			if other.Info().Type == svc.Info().Type {
				typeStillServed = true
				break
			}
		}
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	info := svc.Info()
	r.withdraw(ctx, info.Type, info.Name)
	if !typeStillServed {
		r.withdraw(ctx, info.Type, "")
	}
	if err := svc.Teardown(); err != nil {
		logger.Errorf("[ServiceRegistry] Teardown %s: %v", name, err)
	}
	logger.Infof("[ServiceRegistry] Unregistered %s", name)
	return nil
}

func (r *ServiceRegistry) provide(ctx context.Context, key []byte, service string, ingress *api.ServiceIngress) error {
	if ingress != nil {
		if ip, ok := r.dht.(ingressDirectoryProvider); ok {
			return ip.ProvideWithIngress(ctx, key, service, ingress)
		}
	}
	return r.dht.Provide(ctx, key, service)
}

// serviceTarget is a service as a record names it, "<type>://<name>".
func serviceTarget(info *api.ServiceInfo) string {
	typeStr, err := api.ServiceTypeToString(info.GetType())
	if err != nil {
		return ""
	}
	return typeStr + "://" + info.GetName()
}

// withdraw removes one of the registry's records from the directory. A
// failure is logged: the record expires on its own within the mesh's
// record TTL.
func (r *ServiceRegistry) withdraw(ctx context.Context, serviceType api.ServiceType, name string) {
	key, err := api.ServiceKey(serviceType, name)
	if err != nil {
		return
	}
	withdrawCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := r.dht.Withdraw(withdrawCtx, key); err != nil && !errors.Is(err, errNoDirectoryRouter) {
		logger.Warnf("[ServiceRegistry] Withdrawing %s/%s from the directory: %v", serviceType, name, err)
	}
}

// WithdrawAll withdraws every registered service's records from the
// directory, by name and by type, as a node does before it leaves the mesh.
func (r *ServiceRegistry) WithdrawAll(ctx context.Context) {
	r.mu.RLock()
	infos := make([]*api.ServiceInfo, 0, len(r.services))
	for _, svc := range r.services {
		infos = append(infos, svc.Info())
	}
	r.mu.RUnlock()
	types := map[api.ServiceType]bool{}
	for _, info := range infos {
		r.withdraw(ctx, info.Type, info.Name)
		types[info.Type] = true
	}
	for t := range types {
		r.withdraw(ctx, t, "")
	}
}

// Get returns the service registered under name, if any.
func (r *ServiceRegistry) Get(name string) (Service, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	svc, ok := r.services[name]
	return svc, ok
}

// GetTyped returns the service registered under name only if it is of type
// t. Dispatch after authorization must use this: the policy was evaluated
// on t://name, and a service of another type under that name is not what
// the caller was granted.
func (r *ServiceRegistry) GetTyped(t api.ServiceType, name string) (Service, bool) {
	svc, ok := r.Get(name)
	if !ok || svc.Info().Type != t {
		return nil, false
	}
	return svc, true
}

// List returns the ServiceInfo for every registered service, optionally
// filtered by type. SERVICE_TYPE_UNSPECIFIED means "all types."
func (r *ServiceRegistry) List(typeFilter api.ServiceType) []*api.ServiceInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := []*api.ServiceInfo{}
	for _, svc := range r.services {
		info := svc.Info()
		if typeFilter != api.ServiceType_SERVICE_TYPE_UNSPECIFIED && info.Type != typeFilter {
			continue
		}
		out = append(out, info)
	}
	return out
}

// insertService inserts a service into the registry without calling Init or
// advertising on the DHT. For tests only.
func (r *ServiceRegistry) insertService(svc Service) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[svc.Info().Name] = svc
}

// TeardownAll calls Teardown on every registered service and clears the
// map. Per-service errors are logged; iteration continues.
func (r *ServiceRegistry) TeardownAll() {
	r.mu.Lock()
	svcs := r.services
	r.services = map[string]Service{}
	r.mu.Unlock()
	for name, svc := range svcs {
		if err := svc.Teardown(); err != nil {
			logger.Errorf("[ServiceRegistry] Teardown %s: %v", name, err)
		}
	}
}

// ReprovideAll re-provides all registered services to the DHT concurrently and
// reports how many were withheld because their backend did not answer.
// A service whose backend has stopped answering falls out of the DHT by not
// being reprovided, and returns on a later tick once it answers again.
func (r *ServiceRegistry) ReprovideAll(ctx context.Context) int {
	r.mu.Lock()
	toProvide := make([]Service, 0, len(r.services))
	for _, svc := range r.services {
		toProvide = append(toProvide, svc)
	}
	r.mu.Unlock()

	var withheld atomic.Int32
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)

Loop:
	for _, svc := range toProvide {
		svc := svc
		select {
		case <-ctx.Done():
			break Loop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func() {
			defer func() {
				<-sem
				wg.Done()
			}()

			info := svc.Info()
			if err := advertisable(ctx, svc, r.backendProbeTimeout); err != nil {
				withheld.Add(1)
				// On shutdown every service fails this way, and saying so
				// would blame backends for the node stopping.
				if ctx.Err() == nil {
					logger.Warnf("[ServiceRegistry] Withholding %s/%s from the directory: backend did not answer: %v", info.Type, info.Name, err)
				}
				return
			}

			for _, name := range []string{info.Name, ""} {
				key, err := api.ServiceKey(info.Type, name)
				if err != nil {
					continue
				}
				var ing *api.ServiceIngress
				if name != "" {
					ing = info.GetIngress()
				}
				provideCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := r.provide(provideCtx, key, serviceTarget(info), ing); err != nil && ctx.Err() == nil {
					logger.Warnf("[ServiceRegistry] Announcing %s/%s again: %v", info.Type, info.Name, err)
				}
				cancel()
			}
		}()
	}
	wg.Wait()
	return int(withheld.Load())
}
