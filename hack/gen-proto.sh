#!/usr/bin/env bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

echo "Installing protobuf Go plugins..."
# Keep in sync with the google.golang.org/protobuf version in go.mod.
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12

echo "Generating Go protobuf code..."
mkdir -p api
protoc --go_out=paths=source_relative:. api/sam.proto
protoc -I third_party/envoy --go_out=paths=source_relative:third_party/envoy \
  third_party/envoy/envoy/type/v3/http_status.proto \
  third_party/envoy/envoy/config/core/v3/base.proto \
  third_party/envoy/envoy/extensions/filters/http/ext_proc/v3/processing_mode.proto \
  third_party/envoy/envoy/service/ext_proc/v3/external_processor.proto

echo "Protobuf generation complete."
