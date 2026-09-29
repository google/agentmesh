REPO_ROOT:=${CURDIR}
OUT_DIR=$(REPO_ROOT)/bin
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo devel)
VERSION_LDFLAGS = -X github.com/google/sam/internal/version.Version=$(VERSION)

.DEFAULT_GOAL := build

# disable CGO by default for static binaries
CGO_ENABLED=0
export GOROOT GO111MODULE CGO_ENABLED

# Autodetect Android SDK and NDK
ANDROID_HOME_RESOLVED:=$(if $(ANDROID_HOME),$(ANDROID_HOME),$(firstword $(wildcard $(HOME)/Android/Sdk $(HOME)/Library/Android/sdk)))
ANDROID_NDK_LATEST:=$(shell ls -d $(ANDROID_HOME_RESOLVED)/ndk/* 2>/dev/null | sort -V | tail -n 1)

UNAME_S := $(shell uname -s)
HOST_OS_NAME := linux-x86_64
ifeq ($(UNAME_S),Darwin)
  HOST_OS_NAME := darwin-x86_64
endif

ANDROID_NDK_TOOLCHAIN=$(ANDROID_NDK_LATEST)/toolchains/llvm/prebuilt/$(HOST_OS_NAME)/bin
ANDROID_CC_ARM64=$(ANDROID_NDK_TOOLCHAIN)/aarch64-linux-android30-clang
ANDROID_CC_X86_64=$(ANDROID_NDK_TOOLCHAIN)/x86_64-linux-android30-clang


build:
	go build -v -ldflags "$(VERSION_LDFLAGS)" -o "$(OUT_DIR)/sam-node" ./cmd/sam-node
	go build -v -o "$(OUT_DIR)/sam-control-plane" ./cmd/sam-control-plane
	go build -v -ldflags "$(VERSION_LDFLAGS)" -o "$(OUT_DIR)/sam-router" ./cmd/sam-router
	go build -v -ldflags "$(VERSION_LDFLAGS)" -o "$(OUT_DIR)/sam-one" ./cmd/sam-one
	go build -v -o "$(OUT_DIR)/mcp-client" ./cmd/mcp-client
	go build -v -o "$(OUT_DIR)/sam-box" ./cmd/sam-box
	go build -v -o "$(OUT_DIR)/sam-bench" ./cmd/sam-bench
	go build -v -o "$(OUT_DIR)/sam-console" ./cmd/sam-console
	# nano-init is a separate module: it carries a userspace TCP stack, which
	# has no business in the dependency graph every other binary builds from.
	go -C cmd/nano-init build -v -o "$(OUT_DIR)/nano-init" .


.PHONY: mobile-ffi-host mobile-ffi-android mobile-ffi-android-x86_64 mobile-ffi-ios mobile-ffi mobile-app-apk mobile-app-apk-emulator mobile-app-bundle
mobile-ffi-host:
	mkdir -p "$(OUT_DIR)"
	CGO_ENABLED=1 go build -v -ldflags "$(VERSION_LDFLAGS)" -buildmode=c-shared -o "$(OUT_DIR)/libsam.so" ./mobile/sam-node-ffi

mobile-ffi-android:
	@if [ -z "$(ANDROID_NDK_LATEST)" ]; then \
		echo "Error: Android NDK not found under $(ANDROID_HOME_RESOLVED)/ndk/. Please install NDK (Side-by-side) via Android Studio or sdkmanager." >&2; \
		exit 1; \
	fi
	GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=$(ANDROID_CC_ARM64) go build -v -ldflags="-checklinkname=0 $(VERSION_LDFLAGS)" -buildmode=c-shared -o "$(OUT_DIR)/android/libsam.so" ./mobile/sam-node-ffi

mobile-ffi-android-x86_64:
	@if [ -z "$(ANDROID_NDK_LATEST)" ]; then \
		echo "Error: Android NDK not found under $(ANDROID_HOME_RESOLVED)/ndk/. Please install NDK (Side-by-side) via Android Studio or sdkmanager." >&2; \
		exit 1; \
	fi
	mkdir -p "$(OUT_DIR)/android-x86_64"
	GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=$(ANDROID_CC_X86_64) go build -v -ldflags="-checklinkname=0 $(VERSION_LDFLAGS)" -buildmode=c-shared -o "$(OUT_DIR)/android-x86_64/libsam.so" ./mobile/sam-node-ffi

mobile-ffi-ios:
	mkdir -p "$(OUT_DIR)/ios"
	GOOS=ios GOARCH=arm64 CGO_ENABLED=1 go build -v -ldflags "$(VERSION_LDFLAGS)" -buildmode=c-archive -o "$(OUT_DIR)/ios/libsam.a" ./mobile/sam-node-ffi

mobile-ffi: mobile-ffi-host mobile-ffi-android mobile-ffi-android-x86_64 mobile-ffi-ios

MOBILE_APP_DIR=mobile/sam-node-app
# Optional overrides of pubspec.yaml's `version: X.Y.Z+N`. Google Play rejects
# a bundle whose versionCode (N) it has already seen, so CI passes a fresh one.
MOBILE_BUILD_NAME?=
MOBILE_BUILD_NUMBER?=
MOBILE_FLUTTER_BUILD_FLAGS=$(if $(MOBILE_BUILD_NAME),--build-name=$(MOBILE_BUILD_NAME)) $(if $(MOBILE_BUILD_NUMBER),--build-number=$(MOBILE_BUILD_NUMBER))

.PHONY: mobile-app-google-services
mobile-app-google-services:
	@if [ -n "$$GOOGLE_SERVICES_JSON" ]; then \
		echo "Decoding google-services.json from GOOGLE_SERVICES_JSON environment variable..."; \
		echo "$$GOOGLE_SERVICES_JSON" | base64 --decode > $(MOBILE_APP_DIR)/android/app/google-services.json; \
	elif [ -n "$$GOOGLE_SERVICES_JSON_BASE64" ]; then \
		echo "Decoding google-services.json from GOOGLE_SERVICES_JSON_BASE64 environment variable..."; \
		echo "$$GOOGLE_SERVICES_JSON_BASE64" | base64 --decode > $(MOBILE_APP_DIR)/android/app/google-services.json; \
	elif [ ! -f $(MOBILE_APP_DIR)/android/app/google-services.json ]; then \
		if [ -f $(MOBILE_APP_DIR)/android/app/google-services.json.tmpl ]; then \
			echo "Copying google-services.json from template..."; \
			cp $(MOBILE_APP_DIR)/android/app/google-services.json.tmpl $(MOBILE_APP_DIR)/android/app/google-services.json; \
		else \
			echo "Error: google-services.json is missing."; \
			echo "Please set GOOGLE_SERVICES_JSON or GOOGLE_SERVICES_JSON_BASE64 environment variable with the base64-encoded configuration, or place the file directly at $(MOBILE_APP_DIR)/android/app/google-services.json"; \
			exit 1; \
		fi; \
	fi

.PHONY: mobile-app-jnilibs-arm64 mobile-app-jnilibs-x86_64
mobile-app-jnilibs-arm64: mobile-ffi-android
	mkdir -p $(MOBILE_APP_DIR)/android/app/src/main/jniLibs/arm64-v8a
	cp "$(OUT_DIR)/android/libsam.so" $(MOBILE_APP_DIR)/android/app/src/main/jniLibs/arm64-v8a/libsam.so

mobile-app-jnilibs-x86_64: mobile-ffi-android-x86_64
	mkdir -p $(MOBILE_APP_DIR)/android/app/src/main/jniLibs/x86_64
	cp "$(OUT_DIR)/android-x86_64/libsam.so" $(MOBILE_APP_DIR)/android/app/src/main/jniLibs/x86_64/libsam.so

mobile-app-apk: mobile-app-jnilibs-arm64 mobile-app-jnilibs-x86_64 mobile-app-google-services
	cd $(MOBILE_APP_DIR) && flutter build apk --release --target-platform android-arm64,android-x64 $(MOBILE_FLUTTER_BUILD_FLAGS)

mobile-app-apk-emulator: mobile-app-jnilibs-x86_64 mobile-app-google-services
	cd $(MOBILE_APP_DIR) && flutter build apk --release $(MOBILE_FLUTTER_BUILD_FLAGS)

# Android App Bundle for Google Play. Play rejects debug-signed bundles, so an
# upload key is required: either $(MOBILE_APP_DIR)/android/key.properties or
# the ANDROID_KEYSTORE_PATH / ANDROID_KEYSTORE_PASSWORD / ANDROID_KEY_ALIAS /
# ANDROID_KEY_PASSWORD environment variables (see mobile/sam-node-app/README.md).
#
# Play serves each device the split for its own ABI, so the bundle must only
# contain ABIs that have a libsam.so: Flutter's default set also includes
# armeabi-v7a, which would install and then die opening the FFI library.
.PHONY: mobile-app-bundle
mobile-app-bundle: mobile-app-jnilibs-arm64 mobile-app-jnilibs-x86_64 mobile-app-google-services
	@if [ ! -f $(MOBILE_APP_DIR)/android/key.properties ] && \
	   { [ -z "$$ANDROID_KEYSTORE_PATH" ] || [ -z "$$ANDROID_KEYSTORE_PASSWORD" ] || [ -z "$$ANDROID_KEY_ALIAS" ] || [ -z "$$ANDROID_KEY_PASSWORD" ]; }; then \
		echo "Error: no upload key configured; Google Play rejects debug-signed bundles." >&2; \
		echo "Create $(MOBILE_APP_DIR)/android/key.properties or export ANDROID_KEYSTORE_PATH, ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS and ANDROID_KEY_PASSWORD. See $(MOBILE_APP_DIR)/README.md#publishing-to-google-play." >&2; \
		exit 1; \
	fi
	cd $(MOBILE_APP_DIR) && flutter build appbundle --release --target-platform android-arm64,android-x64 $(MOBILE_FLUTTER_BUILD_FLAGS)
	@echo "Bundle: $(MOBILE_APP_DIR)/build/app/outputs/bundle/release/app-release.aab"

.PHONY: proto
proto:
	./hack/gen-proto.sh

clean:
	rm -rf "$(OUT_DIR)/"

.PHONY: kind-up kind-logs kind-down
kind-up:
	./development/kind/run.sh $(ARGS)

kind-logs:
	./development/kind/run.sh -l

kind-down:
	./development/kind/run.sh -d

.PHONY: kind-local-node
kind-local-node:
	./development/kind/run-local-node.sh $(ARGS)

.PHONY: kind-e2e-mesh
kind-e2e-mesh: build
	./development/kind/test-mesh-e2e.sh

# A mesh of your own on port 8080. In a GitHub codespace the port is
# published on the codespace's https URL; anywhere else this is a local
# sam-one. Uses ./bin/sam-one when built, else sam-one on PATH. State lives
# in ./.sam-one (ignored by git; in a codespace it survives rebuilds). Extra
# flags pass through: make testnet ARGS="--issuer https://accounts.google.com".
SAM_ONE_BIN ?= $(if $(wildcard $(OUT_DIR)/sam-one),$(OUT_DIR)/sam-one,sam-one)
SAM_ONE_DATA_DIR ?= $(REPO_ROOT)/.sam-one
.PHONY: testnet
testnet:
	$(SAM_ONE_BIN) --data-dir "$(SAM_ONE_DATA_DIR)" --port 8080 $(if $(CODESPACE_NAME),--tunnel codespaces) $(ARGS)

test:
	CGO_ENABLED=1 go test -v -race -count 1 $(if $(WHAT),-run $(WHAT)) ./...
	CGO_ENABLED=1 go -C cmd/nano-init test -race -count 1 $(if $(WHAT),-run $(WHAT)) ./...

e2e-test: build docker-build
	bats -j 10 --verbose-run $(if $(WHAT),--filter "$(WHAT)") tests/e2e/

# Native SDKs under sdk/. sdk-js and sdk-python run each SDK's own unit
# tests and leave it installed, which is what TestNativeSDKs needs to run
# both against a real control plane instead of skipping. sdk-js also
# compiles the example programs the docs embed; TestNativeSDKExamples runs
# them.
.PHONY: sdk-js sdk-python sdk-proto sdk-docs sdk-test
sdk-js:
	cd sdk/js && npm ci --no-fund --no-audit && npm test && npm run build && npm run examples

sdk-python:
	python3 -m venv sdk/python/.venv
	./sdk/python/.venv/bin/pip install -q -e './sdk/python[test,examples]'
	./sdk/python/.venv/bin/python -m pytest -q sdk/python/tests

sdk-proto:
	./hack/gen-sdk-proto.sh

sdk-docs:
	go run ./hack/gen-sdk-docs sdk site/content/docs

sdk-test: sdk-js sdk-python
	go test ./tests/integration -run TestNativeSDK -count=1 -v

.PHONY: ui-test
ui-test: build
	chmod +x ./tests/ui/run.sh
	./tests/ui/run.sh $(if $(WHAT),--grep "$(WHAT)")

# Same stack as ui-test, seeded and left running so you can click around.
.PHONY: ui-dev
ui-dev: build
	chmod +x ./tests/ui/dev.sh
	./tests/ui/dev.sh

test-e2e: build docker-build
	@command -v bats >/dev/null 2>&1 || { \
		echo "bats not found; attempting install"; \
		if command -v apt-get >/dev/null 2>&1; then \
			sudo apt-get update && sudo apt-get install -y bats; \
		elif command -v brew >/dev/null 2>&1; then \
			brew install bats-core; \
		else \
			echo "Please install bats-core (https://bats-core.readthedocs.io/)"; \
			exit 1; \
		fi; \
	}
	SAM_NODE_BINARY=$(OUT_DIR)/sam-node SAM_CONTROL_PLANE_BINARY=$(OUT_DIR)/sam-control-plane SAM_ROUTER_BINARY=$(OUT_DIR)/sam-router bats --verbose-run tests/e2e/

test-e2e-container: build docker-build
	@command -v docker >/dev/null 2>&1 || { echo "docker not found"; exit 1; }
	@docker info >/dev/null 2>&1 || { echo "docker daemon is not running"; exit 1; }
	@command -v bats >/dev/null 2>&1 || { echo "bats not found"; exit 1; }
	bats --verbose-run tests/e2e/container_mesh.bats

# code formatters
.PHONY: fmt
fmt:
	go fmt ./...

# code linters
.PHONY: helm-lint
helm-lint:
	@HELM_BIN="helm"; \
	if ! command -v helm >/dev/null 2>&1; then \
		if [ -x "./bin/helm" ]; then \
			HELM_BIN="./bin/helm"; \
		else \
			echo "helm not found; please install helm or place it in ./bin/helm" >&2; \
			exit 1; \
		fi; \
	fi; \
	$$HELM_BIN lint ./charts/sam-mesh && $$HELM_BIN lint ./charts/sam-node --set controlPlaneUrl=http://required-for-lint:8080

# render the chart to bin/chart/ for inspection; pass extra flags via ARGS, e.g. ARGS="--set gateway.enabled=true"
.PHONY: helm-template
helm-template:
	rm -rf bin/chart
	helm template sam-mesh ./charts/sam-mesh --output-dir bin/chart $(ARGS)

lint: fmt helm-lint
	hack/lint.sh

# fast chart template checks; no cluster needed
.PHONY: helm-test
helm-test:
	@helm plugin list 2>/dev/null | grep -q '^unittest' || helm plugin install https://github.com/helm-unittest/helm-unittest --version 0.8.2
	helm unittest charts/sam-mesh charts/sam-node

.PHONY: verify
verify:
	./hack/verify-generated.sh
	./hack/verify-secrets.sh

update:
	go mod tidy

docker-build-control-plane:
	docker build --load -t sam-control-plane:local -f Dockerfile.sam-control-plane .

docker-build-router:
	docker build --load --build-arg VERSION="$(VERSION)" -t sam-router:local -f Dockerfile.sam-router .

docker-build-node:
	docker build --load --build-arg VERSION="$(VERSION)" -t sam-node:local -f Dockerfile.sam-node .

docker-build-mock-oidc:
	docker build --load -t sam-mock-oidc:local -f tests/e2e/docker/Dockerfile.mock-oidc .

docker-build-e2e-runtime:
	docker build --load -t sam-e2e-runtime:local -f tests/e2e/docker/Dockerfile.sam-runtime .

docker-build-nano-init:
	docker build --load -t sam-nano-init:local -f Dockerfile.nano-init .

docker-build-sam-box:
	docker build --load -t sam-box:local -f Dockerfile.sam-box .

docker-build-sam-console:
	docker build --load -t sam-console:local -f Dockerfile.sam-console .

docker-build: docker-build-control-plane docker-build-router docker-build-node docker-build-mock-oidc docker-build-e2e-runtime docker-build-nano-init docker-build-sam-box docker-build-sam-console

.PHONY: docker-build-control-plane docker-build-router docker-build-node docker-build-mock-oidc docker-build-e2e-runtime docker-build-nano-init docker-build-sam-box docker-build-sam-console docker-build
