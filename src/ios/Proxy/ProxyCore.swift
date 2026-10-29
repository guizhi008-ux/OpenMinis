import Foundation

/// Controls the embedded Xray core (see deps/rclone-mobile/librclone/
/// xray_export.go). The core listens on loopback only; ProxySupport points
/// URLSessions at the HTTP inbound.
final class ProxyCore {
    static let shared = ProxyCore()

    static let httpPort = 10809
    static let socksPort = 10808
    /// LAN-facing HTTP inbound for the embedded Linux environment, whose
    /// loopback is isolated from the host's. Password-protected.
    static let lanHTTPPort = 10810

    private(set) var lastError: String = ""

    var isRunning: Bool { MinisXrayRunning() != 0 }

    /// Starts (or restarts) the core from the current settings.
    /// Safe to call from any thread; the C call blocks until the core is up.
    func start() {
        let settings = ProxySettings.shared
        guard settings.isConfigured else {
            lastError = "节点信息不完整"
            return
        }
        guard let json = Self.buildConfigJSON(settings: settings) else {
            lastError = "配置生成失败"
            return
        }
        if let dir = Bundle.main.resourcePath {
            dir.withCString { MinisXraySetAssetDir(UnsafeMutablePointer(mutating: $0)) }
        }
        let result: String = json.withCString { ptr in
            guard let out = MinisXrayStart(UnsafeMutablePointer(mutating: ptr)) else { return "" }
            defer { MinisRcloneFreeString(out) }
            return String(cString: out)
        }
        lastError = result
        if result.isEmpty {
            ProxySupport.syncGuestProxyEnv()
        }
        if result.isEmpty, settings.routingMode == "config", !Self.geoDataAvailable {
            lastError = "分流数据缺失，已按全局代理启动"
        }
    }

    func stop() {
        MinisXrayStop()
        lastError = ""
        ProxySupport.syncGuestProxyEnv()
    }

    func restart() {
        stop()
        start()
    }

    // MARK: - Xray config

    static func buildConfigJSON(settings: ProxySettings) -> String? {
        let outbound: [String: Any]
        switch settings.proto {
        case .ss:
            outbound = [
                "tag": "proxy",
                "protocol": "shadowsocks",
                "settings": [
                    "servers": [[
                        "address": settings.ssServer,
                        "port": settings.ssPort,
                        "method": settings.ssMethod,
                        "password": settings.ssPassword,
                    ]],
                ],
            ]
        case .vless:
            var user: [String: Any] = [
                "id": settings.vlessUUID,
                "encryption": "none",
            ]
            if !settings.vlessFlow.isEmpty {
                user["flow"] = settings.vlessFlow
            }
            var stream: [String: Any] = [
                "network": "tcp",
                "security": settings.vlessSecurity,
            ]
            switch settings.vlessSecurity {
            case "reality":
                stream["realitySettings"] = [
                    "serverName": settings.vlessSNI,
                    "fingerprint": settings.vlessFingerprint,
                    "publicKey": settings.vlessPublicKey,
                    "shortId": settings.vlessShortID,
                    "spiderX": "",
                ]
            case "tls":
                stream["tlsSettings"] = [
                    "serverName": settings.vlessSNI,
                    "fingerprint": settings.vlessFingerprint,
                    "allowInsecure": false,
                ]
            default:
                break
            }
            outbound = [
                "tag": "proxy",
                "protocol": "vless",
                "settings": [
                    "vnext": [[
                        "address": settings.vlessServer,
                        "port": settings.vlessPort,
                        "users": [user],
                    ]],
                ],
                "streamSettings": stream,
            ]
        }

        var config: [String: Any] = [
            "log": ["loglevel": "warning"],
            "inbounds": [
                [
                    "tag": "http-in",
                    "listen": "127.0.0.1",
                    "port": Self.httpPort,
                    "protocol": "http",
                ],
                [
                    "tag": "socks-in",
                    "listen": "127.0.0.1",
                    "port": Self.socksPort,
                    "protocol": "socks",
                    "settings": ["auth": "noauth", "udp": true],
                ],
                [
                    "tag": "http-lan",
                    "listen": "0.0.0.0",
                    "port": Self.lanHTTPPort,
                    "protocol": "http",
                    "settings": [
                        "accounts": [["user": "minis", "pass": settings.lanSecret]],
                    ],
                ],
            ],
            "outbounds": [
                outbound,
                ["tag": "direct", "protocol": "freedom"],
                ["tag": "block", "protocol": "blackhole"],
            ],
            "routing": routingSection(settings: settings),
        ]
        if settings.routingMode == "config" && Self.geoDataAvailable {
            // DNS is used by the router (IPOnDemand) to decide direct vs
            // proxy for domain targets; proxied connections still carry
            // the original domain to the node.
            config["dns"] = ["servers": ["223.5.5.5", "8.8.8.8"]]
        }
        guard let data = try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Routing

    /// True when geoip.dat + geosite.dat were bundled (CI fetches them from
    /// the Xray-core release matching the embedded core version).
    static var geoDataAvailable: Bool {
        guard let dir = Bundle.main.resourcePath else { return false }
        let fm = FileManager.default
        return fm.fileExists(atPath: dir + "/geoip.dat")
            && fm.fileExists(atPath: dir + "/geosite.dat")
    }

    private static let privateIPRule: [String: Any] = [
        "type": "field",
        "ip": [
            "127.0.0.0/8",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "169.254.0.0/16",
        ],
        "outboundTag": "direct",
    ]

    /// Shadowrocket "Config" semantics in config mode: the user's own
    /// lists win first, then CN domains/IPs go direct, and everything else
    /// falls through to the node (the first outbound). Global mode keeps
    /// only the private-range bypass.
    static func routingSection(settings: ProxySettings) -> [String: Any] {
        guard settings.routingMode == "config", geoDataAvailable else {
            return [
                "domainStrategy": "AsIs",
                "rules": [privateIPRule],
            ]
        }
        var rules: [[String: Any]] = []
        if !settings.directDomains.isEmpty {
            rules.append([
                "type": "field",
                "domain": settings.directDomains.map { "domain:" + $0 },
                "outboundTag": "direct",
            ])
        }
        if !settings.proxyDomains.isEmpty {
            rules.append([
                "type": "field",
                "domain": settings.proxyDomains.map { "domain:" + $0 },
                "outboundTag": "proxy",
            ])
        }
        rules.append([
            "type": "field",
            "domain": ["geosite:cn"],
            "outboundTag": "direct",
        ])
        rules.append([
            "type": "field",
            "ip": ["geoip:cn", "geoip:private"],
            "outboundTag": "direct",
        ])
        return [
            "domainStrategy": "IPOnDemand",
            "rules": rules,
        ]
    }
}
