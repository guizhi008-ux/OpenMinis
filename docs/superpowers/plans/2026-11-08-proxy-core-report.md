# App proxy core implementation report

## Interface and ownership

Implemented `deps/rclone-mobile/appproxy/`, `librclone/appproxy_export.go`, and pinned Go module updates. No nethub implementation files were edited by this worker.

C API returns allocated UTF-8 JSON `{ "ok": bool, "data": object, "error"?: safe string }`. Free each response exactly once with `MinisAppProxyFreeString`.

- `MinisAppProxyConfigure(const char*)`: `{mode:"manual"|"node"|"off", manual?:{type:"http"|"https"|"socks5",host,port,username?,password?}, node?:Node, allowBootstrapDNS?:bool}`.
- `MinisAppProxyImport(const char*)`: offline plaintext or whole Base64 URI lists. Returns `{nodes:Node[],issues:[{line,reason}]}`.
- `MinisAppProxyStop(void)`: stops entries and core, leaves `mode:"blocked"` so managed Go routes retain strict intent.
- `MinisAppProxyStatus(void)`: returns `{running,mode,port,httpPort,password}`. Explicit `Configure({mode:"off"})` is the operation that disables managed proxy policy.
- `Node`: `{id:string,name:string,type:"ss"|"vmess"|"vless"|"trojan",outbound:object}`. `outbound` is a credential-bearing sing-box option object; retain it opaque in Keychain. Stable ID hashes normalized outbound options, so label-only duplicates collapse.
- Local client username is `default` (the nethub policy tag), with returned password. Ports are loopback-only, ephemeral, authenticated. Core intermediary credentials are separate and never returned.

## Core and parser

Pinned `github.com/sagernet/sing-box v1.14.4` within the existing module/runtime; no gomobile framework or second Go runtime. Default Go build tags suffice. Runtime registries contain only SOCKS inbound, SS/VMess/VLESS/Trojan outbound, and a hosts-only DNS transport. There is no direct outbound or network DNS transport configured in the core. nethub supplies the authenticated SOCKS/HTTP entries and strict routing; root worker owns UDP chaining, proxied DNS and active-stream shutdown.

Supports SIP002 and legacy whole-authority SS (AEAD and SS2022 methods), VMess v2 JSON, VLESS and Trojan URLs. Explicit handling covers server/port/credentials, VMess alter ID and cipher, TLS/SNI/ALPN/insecure flag, WS path and Host header, gRPC service name, VLESS Vision flow and packet encoding. Percent-encoded URL parameters are decoded once; unknown, duplicate or conflicting parameters are rejected with constant issues. Plugin, Reality, uTLS/fingerprint, HTTPUpgrade, QUIC/KCP and other unimplemented parameters are explicitly rejected. Input is bounded to 1MiB and 2048 nonempty URI line positions; C reads at most 1MiB+1 before the Go size rejection. URI/error text never appears in issue strings.

Server hostnames are retained during import. Configure rejects them unless `allowBootstrapDNS:true` explicitly authorizes server-only system resolution. Resolution happens once with a 10s timeout, then the core receives a pinned IP and original TLS server identity. Business destination names remain in proxy protocol requests and are never resolved through a core network DNS transport. Manual HTTPS bootstrap uses nethub's separate TLS server name field. This policy does not perform subscription URL fetching; Swift owns that disclosed bootstrap workflow.

Configure validates/builds new listeners before replacing the active runtime, and rolls back failures. Switch/Stop closes the old hub and core. Root's strict nethub shutdown closes established streams/associations. Root's Go remote guard and Swift session invalidation must use the blocked/off distinction.

## Validation (Linux, real Go 1.26.10)

Environment: `GOMODCACHE=/workspace/.tools/gomod`, `GOCACHE=/workspace/.tools/gocache`, tool `/workspace/.tools/go/bin/go`. Socket/network tests run outside the default socket-restricted sandbox.

Observed initial failing parser/lifecycle test build before implementations. Further parser test exposed accepted conflicting/discarded parameters, then passed after explicit rejection. Stop lifecycle test exposed mode incorrectly remaining off, then passed after correction.

`go test -race ./appproxy`: PASS. Includes plaintext/whole Base64, SS escaped credentials, encoded WS path, stable deduplication, bounds/invalid ports/unsupported params, VMess fields, all four core constructors, configuration rollback, Stop/off state, and real encrypted Shadowsocks TCP and UDP echo through authenticated nethub -> sing-box SOCKS -> Shadowsocks peer. Destinations bind the container's non-loopback interface address, specifically preventing the intentional localhost bypass from producing a false positive. UDP asserts payload and original remote IP/port.

First `go test ./...`: FAILED. Existing Linux portability error `tsnet/tsnet.go:127: undefined: netmon.UpdateLastKnownDefaultRouteInterface` affects tsnet, cmd/tssmoke, gomobile and librclone. nethub `TestXMapRoutesTheShellsTailnetAndDirectConnections` also intermittently failed at xmap_test.go:63 with `no destination in the file` / connection reset; separate race nethub run passed. netfs and rcloneroute passed. Both failures reported to root for resolution. A stale concurrent run also observed the Stop mode test before its correction; current appproxy race run passes.

Not verified here: macOS c-archive, iOS SDK compilation/linking, Xcode signing, iPhone runtime/suspension, live provider compatibility, all-protocol encrypted egress (SS TCP/UDP is exercised; VMess/VLESS/Trojan constructors are exercised), IPv6 encrypted egress, and external network exit observation.

## License and distribution

sing-box v1.14.4 `LICENSE` states GPL v3-or-later, copyright nekohasekai. Root was notified to add third-party notices and review distribution/source obligations. This Linux build does not establish App Store distribution compatibility.

## Integrated validation addendum

The root integration repaired the pre-existing Linux mobile-netmon build error,
the fakeTailnet test race and the non-atomic xmap test fixture. The complete
staged `go test -race ./...` run now passes for all ten packages (seven contain
tests). Real encrypted TCP and UDP egress tests also pass for VMess, VLESS and
Trojan with local controlled TLS peers, in addition to SS. This supersedes the
earlier constructor-only/all-protocol test limitation above; it does not prove
remote-provider or iPhone behavior.

A Linux c-archive was built, and an actual C program linked and invoked
Configure/Import/Status/Stop/FreeString successfully. A deliberately unpatched
rclone build was tested as a negative control: the C entry point refuses strict
activation because the installed dial-hook marker is missing.
