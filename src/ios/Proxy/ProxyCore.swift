import Foundation

/// Controls the embedded Xray core (see deps/rclone-mobile/librclone/
/// xray_export.go). The core listens on loopback only; ProxySupport points
/// URLSessions at the HTTP inbound.
final class ProxyCore {
    static let shared = ProxyCore()

    static let httpPort = 10809
    static let socksPort = 10808

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
        let result: String = json.withCString { ptr in
            guard let out = MinisXrayStart(UnsafeMutablePointer(mutating: ptr)) else { return "" }
            defer { MinisRcloneFreeString(out) }
            return String(cString: out)
        }
        lastError = result
    }

    func stop() {
        MinisXrayStop()
        lastError = ""
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

        let config: [String: Any] = [
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
            ],
            "outbounds": [
                outbound,
                ["tag": "direct", "protocol": "freedom"],
                ["tag": "block", "protocol": "blackhole"],
            ],
            "routing": [
                "domainStrategy": "AsIs",
                "rules": [[
                    "type": "field",
                    "ip": [
                        "127.0.0.0/8",
                        "10.0.0.0/8",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "169.254.0.0/16",
                    ],
                    "outboundTag": "direct",
                ]],
            ],
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: config, options: [.sortedKeys]) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}
