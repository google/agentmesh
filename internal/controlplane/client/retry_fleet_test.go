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

package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/time/rate"

	"github.com/google/agentmesh/internal/controlplane"
)

// handlerTransport serves requests in process, so thousands of attempts
// cost no sockets.
type handlerTransport struct{ h http.Handler }

func (t handlerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.h.ServeHTTP(rec, r)
	return rec.Result(), nil
}

// TestDoWithChallengeRetryFleet checks the sizing claim in the
// DefaultEnrollBackoff comment: a fleet that starts at once behind the
// control plane's enrollment limiter (EnrollRateLimit a second, burst
// EnrollBurst, refusals answered with the same Retry-After as
// tooManyRequests) is admitted within the budget when it is no larger than
// burst + rate x budget, and past that every member left over gets the
// limiter's last 429 back before the budget runs out. It also checks that
// jitter spreads the fleet out after a shared Retry-After instead of
// bringing it back in lockstep. synctest runs the fleet on a fake clock, so
// minutes of backoff take milliseconds.
func TestDoWithChallengeRetryFleet(t *testing.T) {
	retryAfterSecs := max(1, controlplane.EnrollBurst/controlplane.EnrollRateLimit)
	tests := []struct {
		name    string
		members int
		backoff Backoff
	}{
		{name: "1500 members within the default budget", members: 1500, backoff: DefaultEnrollBackoff},
		{name: "fleet past the budget", members: 600, backoff: Backoff{Initial: time.Second, Max: 15 * time.Second, Budget: 30 * time.Second}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				start := time.Now()

				limiter := rate.NewLimiter(rate.Limit(controlplane.EnrollRateLimit), controlplane.EnrollBurst)
				var mu sync.Mutex
				retries := map[time.Time]int{}
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					now := time.Now()
					if r.Header.Get("X-Attempt") != "1" {
						mu.Lock()
						retries[now]++
						mu.Unlock()
					}
					if !limiter.AllowN(now, 1) {
						w.Header().Set("Retry-After", strconv.Itoa(retryAfterSecs))
						http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
						return
					}
					w.WriteHeader(http.StatusOK)
				})
				httpClient := &http.Client{Transport: handlerTransport{h: handler}}

				type result struct {
					status int
					at     time.Time
				}
				results := make([]result, tc.members)
				var wg sync.WaitGroup
				for i := range tc.members {
					wg.Go(func() {
						attempt := 0
						resp, err := DoWithChallengeRetry(context.Background(), httpClient, time.Now, tc.backoff, func(ts int64) (*http.Request, error) {
							attempt++
							req, err := http.NewRequest(http.MethodPost, "http://control-plane.test/enroll", nil)
							if err == nil {
								req.Header.Set("X-Attempt", strconv.Itoa(attempt))
							}
							return req, err
						})
						if err != nil {
							t.Errorf("member %d: %v", i, err)
							return
						}
						_ = resp.Body.Close()
						results[i] = result{status: resp.StatusCode, at: time.Now()}
					})
				}
				wg.Wait()

				deadline := start.Add(tc.backoff.Budget)
				capacity := controlplane.EnrollBurst + int(float64(controlplane.EnrollRateLimit)*tc.backoff.Budget.Seconds())
				admitted := 0
				for i, r := range results {
					if r.at.After(deadline) {
						t.Errorf("member %d returned at %v, after the %v budget", i, r.at.Sub(start), tc.backoff.Budget)
					}
					switch r.status {
					case http.StatusOK:
						admitted++
					case http.StatusTooManyRequests:
					default:
						t.Errorf("member %d got status %d, want 200 or 429", i, r.status)
					}
				}
				if tc.members <= capacity && admitted != tc.members {
					t.Errorf("admitted %d of %d members within %v, want all (capacity %d)", admitted, tc.members, tc.backoff.Budget, capacity)
				}
				if tc.members > capacity && (admitted == tc.members || admitted > capacity) {
					t.Errorf("admitted %d of %d members, want between 1 and capacity %d with the rest refused", admitted, tc.members, capacity)
				}

				// Everyone refused at the start is told the same Retry-After; with
				// jitter the retries land on many instants, not one.
				busiest, total := 0, 0
				for _, n := range retries {
					busiest = max(busiest, n)
					total += n
				}
				if total == 0 || busiest*10 > total {
					t.Errorf("busiest retry instant took %d of %d retries, want the fleet spread out", busiest, total)
				}
			})
		})
	}
}
