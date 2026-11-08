# SDD ledger — plan: docs/superpowers/plans/2026-11-08-ios-proxy.md

Design approved by user: 2026-11-08.
Execution: started native, then divided independent Go/native/guest/system subsystems between workers; root integrates and verifies without another approval gate.
Ruling: use the dedicated newly cloned checkout on a feature branch — no pre-existing user checkout is being modified; avoids a redundant worktree and preserves reviewability.
Pre-flight: Task 2 Config.Strict is opt-in for Android compatibility. Task 3 core shares the existing Go module/runtime. Tasks 4–7 consume the same active snapshot and entry; no global VPN.
Task 1: Linux feasibility verified. Installed official checksum-verified Go 1.26.10 under /workspace/.tools; existing /usr/bin/go was the GNU board game. Core uses sing-box v1.14.4 in the existing runtime. Swift, Apple SDK, Xcode and an iPhone are absent.
Task 2: strict nethub TCP/UDP/DNS policy and shutdown implemented; full -race suite passes. Existing fakeTailnet fixture race and non-atomic xmap fixture write repaired after observed failures.
Task 3: parser and core lifecycle implemented; real encrypted SS/VMess/VLESS/Trojan TCP/UDP loopback integration passes, with targets on non-loopback interface to prevent false bypass success.
Task 4: Swift settings/Keychain/startup/session generation source implemented; XCTest added but not run. Constructor and project-reference consistency checks pass; they do not certify compilation.
Task 5: guest adapter source completed. Independent review findings (loopback listeners, UDP readiness and residual accept timeout/interruption) fixed and scoped re-review clear. Root independently reran all six normal and ASan/UBSan executables including a real 31-second idle accept; both exit 0. Darwin/kqueue/Python/node-on-iPhone still require platform validation.
Task 6: WebKit configurations and native/system guards implemented. rclone central dialer staged from hash-pinned source, covering HTTP and non-HTTP transports. OS-owned Keychain/APNs/prior delegated tasks remain explicit boundaries.
Task 7: Linux integration validation complete; Apple platform validation pending. All 10 Go packages build/test under staged -race run (7 contain tests). Linux c-archive and real C configure/import/status/stop/free calls pass. Deliberately unpatched library refuses strict activation. Xcode test script exits 127: xcodebuild unavailable; no iPhone verification claim.
Ruling: split independent subsystem work between workers — avoids sequential integration blind spots while preserving file ownership; mistakes cost review/fix time.
Ruling: Go rejects overlays under GOMODCACHE, so stage a disposable full copy of pinned rclone and use an alternate modfile plus single-file overlay — cache stays immutable; rclone upgrades require fingerprint review.
Ruling: retain existing synchronizable provider/environment credentials and document system Keychain traffic outside the controllable boundary — avoids credential loss or stale-token migration; cannot promise app-owned control over iOS Keychain synchronization.

Final fresh uncached Go -race suite: PASS all ten packages. A run exposed two existing asynchronous log-observation fixture races (TestEntryLogsStageOnFailure, TestUDPSpoofedSourceDropped); tests now await the actual logged event rather than assuming protocol reply/counter increments synchronize logging. Final suite rerun passed.
Native Apple-framework source remains uncompiled in this environment; no IPA or shipped-iPhone claim.
Independent review: original P1 local-service and UDP readiness findings plus residual P2 accept wait all fixed; no outstanding material scoped findings.
Delivery: retain dedicated feature branch/check-out for user review; no upstream push/merge/publication requested.
