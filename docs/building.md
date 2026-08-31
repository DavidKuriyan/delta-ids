# Building Delta-NIDS

Delta-NIDS uses CMake as its single build-system source of truth and requires C++17 or newer.

## Configure and build

```bash
cmake -S . -B build -DDELTA_NIDS_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

For a release build:

```bash
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release
cmake --build build-release
```

On Windows, the same commands work from a Developer PowerShell. Ninja may be selected with:

```text
-G Ninja
```

## Compiler diagnostics

Warnings are enabled by default. Maintainers may enable warning-as-error mode with:

```bash
-DDELTA_NIDS_ENABLE_WERROR=ON
```

This should be enabled in CI after all supported compiler warnings have been reviewed.

## Dependency strategy

The Phase 3 foundation intentionally has no third-party runtime dependencies. Future dependencies must:

1. build on supported Linux and Windows toolchains;
2. have a compatible license documented in the repository;
3. be selected through CMake rather than handwritten platform-specific build commands;
4. be isolated behind a Delta-NIDS abstraction when they provide operating-system services.

Current dependencies include libpcap/Npcap and nlohmann-json. If nlohmann-json is not installed, CMake FetchContent downloads pinned release v3.11.3 during configuration. Planned dependency categories are configuration parsing, SQLite, HTTP, and testing; each will be enabled only after its portability requirements are implemented.

## Rule validation

Validate passive Delta-NIDS rules with:

```bash
./build/delta-nids --validate-rules tests/fixtures/valid.rules.json
```

The rule parser rejects active actions such as `DROP`, `REJECT`, `BLOCK`, and `REPLACE`.

## Current scope

The current executable validates the CMake, core-library, and platform-boundary structure. It does not yet capture packets or perform detection. Those features are introduced in later phases and must not be inferred from this bootstrap executable.
