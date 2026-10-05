# Vendored Envoy `ext_proc` v3 Protobufs

This directory contains trimmed `.proto` definitions from `github.com/envoyproxy/envoy` (`api/envoy/`) for the `envoy.service.ext_proc.v3.ExternalProcessor` protocol:

* `envoy/service/ext_proc/v3/external_processor.proto`
* `envoy/extensions/filters/http/ext_proc/v3/processing_mode.proto`
* `envoy/config/core/v3/base.proto` (trimmed to `HeaderValue`, `HeaderValueOption`, `HeaderMap`, `Metadata`)
* `envoy/type/v3/http_status.proto`

## Why Trimmed & Vendored

SAM speaks `envoy.service.ext_proc.v3.ExternalProcessor` over standard-library HTTP/2 gRPC framing (`net/http`) without adding `github.com/envoyproxy/go-control-plane` or `google.golang.org/grpc` to the root `go.mod`. Removing annotation-only imports (`validate`, `udpa`, `xds`, `envoy.annotations`) leaves protobuf package names, message names, and wire field numbers 100% identical to upstream Envoy.

## Regenerating

Run `./hack/gen-proto.sh` from the repository root.
