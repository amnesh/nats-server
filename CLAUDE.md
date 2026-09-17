# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## This repository is a fork

`origin` is a fork of nats-io/nats-server (`upstream`). Run `git remote -v` before any push. The fork keeps a small set of custom features as commits on top of an upstream `release/vX.Y.Z` branch. There is no fork development on `main`; work lands on the current release branch as small, self-contained commits.

- The custom commits are exactly `git log upstream/release/vX.Y.Z..origin/release/vX.Y.Z`. Each feature is one squashed, signed-off commit, so it cherry-picks cleanly onto the next upstream release.
- Keep feature logic in dedicated files and add only the smallest hooks to upstream files, so cherry-picks stay conflict-free. Existing examples: `server/authverify/` + `server/auth_verification.go` (post-auth verification callout), `server/soo-changes.go` (`Nats-Request-Info` stamping on inbound requests), `server/auth_perm_macros.go` (`{{kvrw(tag(kv))}}` style permission template macros), and the custom listener/dialer fields in `server/opts.go`.
- Every fork feature is off by default. An unconfigured server behaves like upstream.
- `FORK-CHANGES.md` documents each feature: config keys, wire formats, code map, tests. `docs/superpowers/specs/` holds the design specs. Update both when a feature changes.
- To move the fork to a newer upstream release, use the `update-fork` skill in `.claude/skills/`. The fork tag `vX.Y.Z` points at the fork's top commit, not at upstream's release commit, so `go get <fork>@vX.Y.Z` includes the patches.
- Fork feature tests:

```sh
go test -run 'AuthVerify|RequestInfo|ClientInfoForRequest|SharesRequestUserInfo|TemplateMacro' ./server ./server/authverify ./test -count=1
```

## Build, lint, and test

```sh
go build                                      # build ./nats-server
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.0   # .golangci.yml is a v2 config (matches CI)
golangci-lint run --timeout=5m --config=.golangci.yml
go generate ./server                          # regenerate jetstream_errors_generated.go from server/errors.json
```

The `compile` step in `scripts/runTestsOnTravis.sh` installs a golangci-lint v1 binary, which cannot read the v2 config; use the line above instead. The test scripts pass `-vet=off`; `govet` runs as part of golangci-lint.

CI builds with the minimum Go from `go.mod` and with `stable`, for `GOARCH=amd64` and `GOARCH=386` on Linux, plus Windows. Keep 32-bit builds green (`int`/`int64` sizes, 64-bit atomics need 8-byte alignment).

### Running tests

The full suite takes hours and is split into named CI jobs by `scripts/runTestsOnTravis.sh`. Run individual jobs locally with the same script. CI adds `-race` only for pushes to branches other than `main` and `release/*`, and never for pull requests. Fork work lands on `release/*`, so CI never runs the race detector here; run it locally with `RACE=-race`.

```sh
RACE=-race ./scripts/runTestsOnTravis.sh srv_pkg_non_js_tests
./scripts/runTestsOnTravis.sh js_tests           # JetStream non-clustered
./scripts/runTestsOnTravis.sh js_cluster_tests_1 # one of 4 sharded JS cluster groups
./scripts/runTestsOnTravis.sh no_race_1_tests    # TestNoRace*, must NOT run under -race
./scripts/runTestsOnTravis.sh raft_tests         # TestNRG*
./scripts/runTestsOnTravis.sh store_tests        # TestStore / TestFileStore / TestMemStore
./scripts/runTestsOnTravis.sh jwt_tests          # TestJWT*
./scripts/runTestsOnTravis.sh mqtt_tests         # TestMQTT*
./scripts/runTestsOnTravis.sh msgtrace_tests     # TestMsgTrace*
./scripts/runTestsOnTravis.sh non_srv_pkg_tests  # everything outside ./server/... (includes ./test)
```

Running a single test:

```sh
go test -race -v -run TestNameHere ./server -count=1 -timeout=10m
```

Build tags partition large test groups. To compile a subset locally, mirror what the CI shard uses, e.g. `-tags=skip_js_tests,skip_mqtt_tests,skip_msgtrace_tests,skip_store_tests,skip_no_race_tests`. `TestNoRace*` tests live behind `!race` and must be run without `-race`. `include_js_long_tests` opt-in tag enables very long-running JS cluster tests. Coverage runs through `scripts/cov.sh` (uses `gocovmerge`).

Test naming conventions are load-bearing: the CI shards select tests by prefix, so a wrong prefix silently excludes a test from CI:

| Prefix | Goes in shard |
|---|---|
| `TestJetStream` (non-cluster) | `js_tests` |
| `TestJetStreamCluster` | one of `js_cluster_tests_{1..4}` (controlled by `skip_js_cluster_tests*` tags on the file) |
| `TestJetStreamSuperCluster` | `js_super_cluster_tests` |
| `TestJetStreamConsumer` | `js_consumer_tests` |
| `TestNRG` | `raft_tests` |
| `TestJWT` | `jwt_tests` |
| `TestMQTT` | `mqtt_tests` |
| `TestMsgTrace` | `msgtrace_tests` |
| `TestFileStore` / `TestMemStore` / `TestStore` | `store_tests` |
| `TestNoRace` | `no_race_{1,2}_tests` (no `-race`) |

All other `Test*` in the server package fall into `srv_pkg_non_js_tests`, selected by the regex `^Test(N[^R]|NR[^G]|J[^W]|JW[^T]|[^JN])`. Check that a new top-level name does not match a different shard's exclusion by accident.

## Architecture

NATS Server is the core broker for the NATS messaging system. The entry point `main.go` is intentionally thin: parse flags, build `*server.Options`, call `server.NewServer`, `s.ConfigureLogger`, `server.Run(s)`, and block on `s.WaitForShutdown()`. Everything substantive lives in `./server`.

### The `Server` god-struct

`server/server.go` defines a single large `Server` struct holding listeners, all client maps (`clients`, `routes`, `leafs`), the account registry, JetStream pointer, sublist, system account, signal/HTTP plumbing, and the goroutine WaitGroup. Most subsystems are methods on `*Server`. Two locks coordinate hot paths: `mu` (the server lock) and `reloadMu` (write-locked only during config reload, taken before all other locks so new connections cannot race a reload).

### Connection types share one `client` struct

A single `client` type in `server/client.go` represents every kind of TCP/WS peer: a NATS client, a route to another cluster member, a leaf node, a gateway, an MQTT client, or a WebSocket client. The `kind` field distinguishes them. The shared parser (`server/parser.go`) is a hand-rolled byte-by-byte state machine that handles all NATS-protocol variants. When changing connection logic, check whether the change should apply to one kind or all; code paths are frequently gated on `c.kind`.

### Subsystems (files in `./server`)

- **Client / protocol**: `client.go`, `parser.go`, `proto.go`, `sublist.go`, `auth.go`, `accounts.go`, `nkey.go`, `jwt.go`.
- **Clustering / federation**: `route.go` (cluster routes), `gateway.go` (super-clusters), `leafnode.go` (leaf nodes). Each has its own connect/handshake flow but reuses `client`.
- **JetStream**: `jetstream.go`, `jetstream_api.go`, `jetstream_cluster.go`, `stream.go`, `consumer.go`, plus storage in `filestore.go` and `memstore.go` (both implement `store.go`'s `StreamStore`). JetStream is opt-in (`-js`) and uses Raft (`raft.go`) for replication of stream/consumer state. Errors are code-generated: edit `server/errors.json` then `go generate ./server`.
- **Protocols on top of NATS**: `mqtt.go` (full MQTT 3.1.1 broker), `websocket.go` (WS transport for clients/leaf nodes).
- **Operations**: `monitor.go` (HTTP `/varz`, `/connz`, `/jsz`…), `events.go` (system account `$SYS.>` events), `reload.go` (SIGHUP config reload), `signal.go`, `service.go` / `service_windows.go` (Windows service shim around `Run`).
- **Security / TLS**: `ocsp*.go`, `certstore/`, `certidp/`, `tpm/`, `ciphersuites.go`.
- **Data structures**: `server/sublist.go` (subject subscription tree), `server/stree/` (subject trie used by JetStream), `server/avl/` (AVL-based seq set), `server/gsl/` (generic sublist), `server/thw/` (timer wheel), `server/ipqueue.go`.
- **Config**: top-level `conf/` package is a hand-written lexer/parser for the NATS config dialect (it is **not** HCL/JSON). `server/opts.go` maps parsed config to `Options` and is also responsible for option validation and reload diffs.

### Two test directories

- `./server/*_test.go`: white-box tests with access to unexported state. Most of the suite lives here.
- `./test/*_test.go`: black-box integration tests that drive the server over the wire. The CI job `non_srv_pkg_tests` runs `./test` (and other non-`server` packages) via `go test $(go list ./... | grep -v "/server")`.

`server/test_test.go` and `test/test.go` contain shared helpers (cluster builders, JS helpers, NATS client helpers).

### Lock ordering

`locksordering.txt` is authoritative. Read it before adding a new lock or before locking inside a callback, and update it in the same change when a new order is needed. The spine is:

- `reloadMu -> Server -> client -> Account`
- `jetStream -> jsAccount -> Server -> client -> Account`
- `jetStream -> jsAccount -> stream -> consumer`

## Conventions

- **Sign off every commit** (`git commit -s`). Upstream CI rejects PR commits without `Signed-off-by:`, and the fork keeps the same rule on its release branches.
- The linter forbids `fmt.Print*` outside `main.go`, `server/opts.go`, `_test.go`, and a single allow-listed line in `server.go`. Use the server's `Logger` instead. US English spelling (`misspell` linter, `locale: US`).
- New external dependencies are heavily scrutinized; prefer not to add any. Update `DEPENDENCIES.md` if you do.
- `//go:build ignore` files (e.g. `server/errors_gen.go`) are generators run via `go generate`, not compiled into the server.
