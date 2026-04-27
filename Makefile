.PHONY: build static-lib configure test test-core test-go test-swift test-wasm
.PHONY: test-spm-layout test-artifactbundle-split test-github-workflows
.PHONY: ensure-artifactbundle ensure-apple-artifactbundle ensure-android-artifactbundle
.PHONY: ensure-placeholder-apple-artifactbundle ensure-placeholder-android-artifactbundle
.PHONY: artifactbundle artifactbundle-apple artifactbundle-android clean check-submodule
.PHONY: sync-go-bindings release

BUILD_DIR ?= build
CMAKE_BUILD_TYPE ?= Release
ARTIFACTBUNDLE_BUILD_ROOT ?= $(CURDIR)/build/artifactbundle
APPLE_ARTIFACTBUNDLE ?= AttestedKeyZKApple.artifactbundle
ANDROID_ARTIFACTBUNDLE ?= AttestedKeyZKAndroid.artifactbundle
APPLE_BINARY_TARGET_NAME ?= CAttestedKeyZKAppleBinary
ANDROID_BINARY_TARGET_NAME ?= CAttestedKeyZKAndroidBinary
SWIFTPM_PLACEHOLDER_MARKER := .swiftpm-placeholder

build: configure
	cmake --build $(BUILD_DIR) -j

configure: check-submodule
	cmake -S . -B $(BUILD_DIR) -D CMAKE_BUILD_TYPE=$(CMAKE_BUILD_TYPE)

check-submodule:
	@test -f third_party/longfellow-zk/lib/CMakeLists.txt || \
		(echo "Missing google/longfellow-zk submodule. Run: git submodule update --init --recursive" && exit 1)

static-lib: build

test: test-core test-go test-swift test-github-workflows

test-core: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

sync-go-bindings: check-submodule
	./scripts/sync-go-bindings.sh

test-go: sync-go-bindings
	cd bindings/go && GOWORK=off go test ./...

ensure-artifactbundle: ensure-apple-artifactbundle ensure-android-artifactbundle
	@echo "==> Apple and Android artifact bundles are ready"

ensure-apple-artifactbundle:
	@if ATTESTED_KEY_ZK_SWIFTPM_PLACEHOLDER_MARKER="$(SWIFTPM_PLACEHOLDER_MARKER)" ./check-apple-artifactbundle.py "$(APPLE_ARTIFACTBUNDLE)"; then \
		echo "==> Apple artifact bundle already matches SwiftPM requirements"; \
	elif [ -f "$(ARTIFACTBUNDLE_BUILD_ROOT)/targets/ios-arm64/libattested_key_zk.a" ] && \
	     [ -f "$(ARTIFACTBUNDLE_BUILD_ROOT)/targets/ios-arm64-simulator/libattested_key_zk.a" ] && \
	     [ -f "$(ARTIFACTBUNDLE_BUILD_ROOT)/targets/macos-arm64/libattested_key_zk.a" ]; then \
		echo "==> Repackaging Apple artifact bundle from existing static libraries..."; \
		ATTESTED_KEY_ZK_BUILD_ROOT="$(ARTIFACTBUNDLE_BUILD_ROOT)" \
		ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(APPLE_ARTIFACTBUNDLE)" \
		ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(APPLE_BINARY_TARGET_NAME)" \
		./build-artifactbundle.sh --apple-only --skip-build; \
	else \
		echo "==> Building Apple artifact bundle..."; \
		ATTESTED_KEY_ZK_BUILD_ROOT="$(ARTIFACTBUNDLE_BUILD_ROOT)" \
		ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(APPLE_ARTIFACTBUNDLE)" \
		ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(APPLE_BINARY_TARGET_NAME)" \
		./build-artifactbundle.sh --apple-only; \
	fi
	@$(MAKE) ensure-placeholder-android-artifactbundle

ensure-android-artifactbundle:
	@if ATTESTED_KEY_ZK_SWIFTPM_PLACEHOLDER_MARKER="$(SWIFTPM_PLACEHOLDER_MARKER)" ./check-android-artifactbundle.py "$(ANDROID_ARTIFACTBUNDLE)"; then \
		echo "==> Android artifact bundle already matches SwiftPM requirements"; \
	elif [ -f "$(ARTIFACTBUNDLE_BUILD_ROOT)/targets/android-aarch64/libattested_key_zk.a" ] && \
	     [ -f "$(ARTIFACTBUNDLE_BUILD_ROOT)/targets/android-x86_64/libattested_key_zk.a" ]; then \
		echo "==> Repackaging Android artifact bundle from existing static libraries..."; \
		ATTESTED_KEY_ZK_BUILD_ROOT="$(ARTIFACTBUNDLE_BUILD_ROOT)" \
		ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(ANDROID_ARTIFACTBUNDLE)" \
		ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(ANDROID_BINARY_TARGET_NAME)" \
		./build-artifactbundle.sh --android-only --skip-build; \
	else \
		echo "==> Building Android artifact bundle..."; \
		ATTESTED_KEY_ZK_BUILD_ROOT="$(ARTIFACTBUNDLE_BUILD_ROOT)" \
		ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(ANDROID_ARTIFACTBUNDLE)" \
		ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(ANDROID_BINARY_TARGET_NAME)" \
		./build-artifactbundle.sh --android-only; \
	fi
	@$(MAKE) ensure-placeholder-apple-artifactbundle

ensure-placeholder-apple-artifactbundle:
	@if [ -e "$(APPLE_ARTIFACTBUNDLE)" ] && [ -f "$(APPLE_ARTIFACTBUNDLE)/info.json" ]; then \
		if [ -f "$(APPLE_ARTIFACTBUNDLE)/$(SWIFTPM_PLACEHOLDER_MARKER)" ]; then \
			echo "==> Apple placeholder artifact bundle already exists for SwiftPM resolution"; \
		else \
			echo "==> Apple artifact bundle already exists for SwiftPM resolution"; \
		fi; \
	else \
		if [ -e "$(APPLE_ARTIFACTBUNDLE)" ]; then \
			echo "==> Apple artifact bundle is incomplete; rebuilding SwiftPM placeholder..."; \
			rm -rf "$(APPLE_ARTIFACTBUNDLE)"; \
		else \
			echo "==> Creating SwiftPM placeholder Apple artifact bundle..."; \
		fi; \
		set -e; \
		tmp_root="$$(mktemp -d)"; \
		trap 'rm -rf "$$tmp_root"' EXIT; \
		mkdir -p "$$tmp_root/targets/ios-arm64" "$$tmp_root/targets/ios-arm64-simulator" "$$tmp_root/targets/macos-arm64"; \
		: > "$$tmp_root/targets/ios-arm64/libattested_key_zk.a"; \
		: > "$$tmp_root/targets/ios-arm64-simulator/libattested_key_zk.a"; \
		: > "$$tmp_root/targets/macos-arm64/libattested_key_zk.a"; \
		ATTESTED_KEY_ZK_BUILD_ROOT="$$tmp_root" \
		ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(APPLE_ARTIFACTBUNDLE)" \
		ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(APPLE_BINARY_TARGET_NAME)" \
		./build-artifactbundle.sh --apple-only --skip-build; \
		touch "$(APPLE_ARTIFACTBUNDLE)/$(SWIFTPM_PLACEHOLDER_MARKER)"; \
	fi

ensure-placeholder-android-artifactbundle:
	@if [ -e "$(ANDROID_ARTIFACTBUNDLE)" ] && [ -f "$(ANDROID_ARTIFACTBUNDLE)/info.json" ]; then \
		if [ -f "$(ANDROID_ARTIFACTBUNDLE)/$(SWIFTPM_PLACEHOLDER_MARKER)" ]; then \
			echo "==> Android placeholder artifact bundle already exists for SwiftPM resolution"; \
		else \
			echo "==> Android artifact bundle already exists for SwiftPM resolution"; \
		fi; \
	else \
		if [ -e "$(ANDROID_ARTIFACTBUNDLE)" ]; then \
			echo "==> Android artifact bundle is incomplete; rebuilding SwiftPM placeholder..."; \
			rm -rf "$(ANDROID_ARTIFACTBUNDLE)"; \
		else \
			echo "==> Creating SwiftPM placeholder Android artifact bundle..."; \
		fi; \
		set -e; \
		tmp_root="$$(mktemp -d)"; \
		trap 'rm -rf "$$tmp_root"' EXIT; \
		mkdir -p "$$tmp_root/targets/android-aarch64" "$$tmp_root/targets/android-x86_64"; \
		: > "$$tmp_root/targets/android-aarch64/libattested_key_zk.a"; \
		: > "$$tmp_root/targets/android-x86_64/libattested_key_zk.a"; \
		ATTESTED_KEY_ZK_BUILD_ROOT="$$tmp_root" \
		ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(ANDROID_ARTIFACTBUNDLE)" \
		ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(ANDROID_BINARY_TARGET_NAME)" \
		./build-artifactbundle.sh --android-only --skip-build; \
		touch "$(ANDROID_ARTIFACTBUNDLE)/$(SWIFTPM_PLACEHOLDER_MARKER)"; \
	fi

test-artifactbundle-split:
	./scripts/tests/test-artifactbundle-split.sh

test-github-workflows:
	./scripts/tests/test-github-workflows.py

test-spm-layout: test-artifactbundle-split ensure-apple-artifactbundle
	./scripts/tests/test-spm-layout.sh

test-swift: test-spm-layout
	@if command -v swift >/dev/null 2>&1; then \
		swift test; \
	else \
		echo "Skipping Swift tests: swift not installed"; \
	fi

test-wasm:
	@command -v emcc >/dev/null 2>&1 || (echo "emcc not found; install Emscripten first" && exit 1)
	cd bindings/wasm && corepack enable && pnpm install --frozen-lockfile && rm -rf dist lib && pnpm build:ts && pnpm test && pnpm build:wasm && pnpm smoke

artifactbundle:
	$(MAKE) artifactbundle-apple
	$(MAKE) artifactbundle-android

artifactbundle-apple:
	ATTESTED_KEY_ZK_BUILD_ROOT="$(ARTIFACTBUNDLE_BUILD_ROOT)" \
	ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(APPLE_ARTIFACTBUNDLE)" \
	ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(APPLE_BINARY_TARGET_NAME)" \
	./build-artifactbundle.sh --apple-only
	@$(MAKE) ensure-placeholder-android-artifactbundle

artifactbundle-android:
	ATTESTED_KEY_ZK_BUILD_ROOT="$(ARTIFACTBUNDLE_BUILD_ROOT)" \
	ATTESTED_KEY_ZK_BUNDLE_OUTPUT="$(ANDROID_ARTIFACTBUNDLE)" \
	ATTESTED_KEY_ZK_BINARY_TARGET_NAME="$(ANDROID_BINARY_TARGET_NAME)" \
	./build-artifactbundle.sh --android-only
	@$(MAKE) ensure-placeholder-apple-artifactbundle

clean:
	rm -rf $(BUILD_DIR) .build $(ARTIFACTBUNDLE_BUILD_ROOT) bindings/swift/.build bindings/wasm/lib bindings/wasm/dist bindings/wasm/node_modules
	rm -rf AttestedKeyZK.artifactbundle $(APPLE_ARTIFACTBUNDLE) $(ANDROID_ARTIFACTBUNDLE)

release:
	@./scripts/release.sh "$(VERSION)"
