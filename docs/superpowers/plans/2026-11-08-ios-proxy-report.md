# iOS app proxy implementation report

## Native iOS configuration and routing

Implemented source (not yet Xcode-compiled):

- `Shared/Proxy/AppProxyNetwork.swift`: immutable route snapshots, initially blocked startup policy, native session factory, typed Apple `Network.ProxyConfiguration` for authenticated loopback HTTP CONNECT, `allowFailover = false`, explicit loopback-only exclusions, generation-based session caches, and cancellation of every registered session on route changes. Existing delegates, SDK protocols, timeouts and cookie/cache settings are retained.
- `Shared/Proxy/AppProxyBridge.swift`: C JSON ABI, sanitized Swift errors, opaque imported outbound JSON retention. Local native username is `default`; guest username is `shell`.
- `Shared/Proxy/AppProxyStore.swift`: Keychain-only credentials, URLs, nodes and bootstrap consent; ordinary preferences store only selected mode. Saved strict intent survives activation failure. Switching enters blocked state and stops the old runtime before replacement. First stored property in `MinisApp` restores policy before coordinator initializers; foreground entry checks runtime status before lifecycle networking.
- `NetworkProxySettingsView`: Off/manual/subscription controls, HTTPS update through an existing proxy, offline text/Base64 import, node choice/deletion, opt-in proxy-server hostname DNS bootstrap, and explicit Apple HTTPS connection test. HTTPS subscription redirects cannot downgrade to plaintext; response body is bounded at 4 MiB. Failed import/update/save retains the previous node list. Removing the selected node blocks traffic until a replacement is selected.
- All native Swift `URLSession.shared` expressions and session constructors were migrated to the factory outside Browser/WebApp (owned by the integration work). Streaming, voice, quota and retained Anthropic SDK adapters acquire sessions by the current generation. Anthropic URLProtocol inner sessions preserve their streaming timeout and delegate.
- Removed unmanaged SwiftUI `AsyncImage` remote loading from markdown media and direct HTTP `Data(contentsOf:)` attachment loading. Remote video attachments download through the controlled session before AVFoundation receives a local temporary file. Other AVFoundation and extension boundaries are tracked by the system-boundary implementation.

Validation actually performed: `git diff --check` passed; a native-source audit found the only remaining direct `URLSession(configuration:)` constructor in the unified factory (excluding tests and Browser/WebApp ownership). These are consistency checks, not runtime proof.

Added `MinisTests/AppProxyNetworkTests.swift` with real Foundation URLProtocol dispatch for unavailable-core rejection before SDK interception, in-flight task cancellation and cached-session replacement, configuration/streaming-policy retention, production configuration-builder rejection of incomplete stored strict modes, manual validation/bootstrap consent and opaque node JSON round-trip. **These tests have not run:** no Swift executable, Apple SDK, Xcode, Simulator or device is available in this Linux workspace. No RED→GREEN claim is made. XCTest/Keychain failure injection, native HTTP CONNECT authentication, native WebSocket behavior, suspend/resume, DNS egress and iPhone exit-IP observations remain required on macOS/iPhone. `URLSession` typed-proxy semantics were checked against official Apple API declarations; actual runtime behavior remains unverified.

Known native implementation limits: AVFoundation remote video attachments are downloaded in full to temporary storage before playback; there is no streaming cache or explicit temporary-file eviction yet. Subscription updates require a working proxy or offline import; there is no direct download bootstrap. Native errors intentionally omit core input and secret-bearing URLs. This implementation does not establish coverage of system-owned networking or guarantee Xcode compilation.

## Integrated delivery validation

Implemented app-only HTTP(S)/SOCKS5 and common Shadowrocket URI-list subscriptions,
with the pinned sing-box core in the existing Go runtime. WebKit stores, native
HTTP/WebSocket sessions, guest sockets, and the staged rclone central dialer use
the configured app path. Strict mode rejects failed routes rather than falling
back. No device VPN/MDM settings are installed or modified.

Root independently observed final results:

- `go test -modfile=.../go.mod -overlay=.../overlay.json -race -count=1 ./...`: PASS
  all ten Go packages (seven contain tests), including encrypted TCP/UDP peers,
  strict DNS, shutdown and SMB/rclone dial interception.
- Six portable C executables: PASS, both normal and ASan/UBSan. Covers stable
  loopback listeners/clients, pre-registered epoll, delayed UDP readiness,
  failure/cancellation wakes, exact datagram metadata, real interrupt, explicit
  receive timeout and actual 31-second idle accept followed by a late client.
- Linux c-archive: builds; real C configure/import/status/strict-state/stop/free
  calls PASS. Unpatched-rclone negative control refuses strict activation.
- Pinned guest patch applies/reapplies; source/project-reference audits, source
  boundary audits, shell syntax and git whitespace checks pass. Source audits
  are not runtime egress evidence.
- Independent review findings on local listeners, UDP readiness and accept
  timeout/interruption were fixed; scoped re-review has no outstanding material
  finding. Full source changes remain available on `feat/ios-app-proxy`.

Final full Go regression initially exposed two old asynchronous logging test
assumptions (`TestEntryLogsStageOnFailure`, `TestUDPSpoofedSourceDropped`). They
now await log completion rather than assuming counter/response ordering; the
subsequent uncached full suite passes. Earlier test-fixture data races and
non-atomic xmap writes were similarly repaired, without changing Android defaults.

Apple weather/maps/geocoding/network-assisted location are gated in strict mode;
supported on-device speech is permitted, with cloud fallback rejected. Newly
added `SystemSpeechProxyBoundaryTests` is an unrun XCTest, like the native proxy
and WebKit tests. Existing iCloud Keychain/APNs and previously delegated jobs
remain OS-owned limitations; saved credentials/settings are retained.

NOT VERIFIED: Swift/Objective-C with Apple SDK, Xcode link/signing, native proxy
authentication/WebSocket/WebKit behavior, Darwin socketpair/kqueue semantics,
real guest programs on iPhone, suspension and actual iPhone exit/DNS capture.
`scripts/ios-unit-tests.sh` was attempted and exits 127 because xcodebuild is
absent. Its static safety check reports zero unexplained accesses and one
pre-existing stale AOJIT allowlist entry. This is a source handoff, not a verified
iPhone build or installable IPA.

Implementation choices and limits: dedicated fresh checkout/feature branch;
independent subsystem workers with root integration; generated, hash-pinned
rclone source staging because Go forbids overlays inside GOMODCACHE; existing
synchronizable credentials retained to avoid stale/lost credential migration.
These choices trade integration/review work and explicit OS limitations for
reproducibility and credential preservation. Core/guest dependency upgrades need
a new compatibility review. Wildcard guest binds are rejected; bind localhost
explicitly. Mixing local/remote destinations on one UDP socket, ancillary IP,
raw/ICMP and source-port preservation remain unsupported and do not silently
bypass. Temporary remote-video downloads do not yet have an eviction policy.
