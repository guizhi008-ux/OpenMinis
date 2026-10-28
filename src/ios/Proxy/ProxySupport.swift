import Foundation
import CFNetwork

/// Wires URLSessions to the embedded proxy core.
///
/// When the proxy is enabled, sessions get a `connectionProxyDictionary`
/// pointing at the core's loopback HTTP inbound. Domain names are passed
/// to the proxy unresolved (HTTP CONNECT), so target DNS is resolved at
/// the node, not locally.
enum ProxySupport {
    static func apply(to config: URLSessionConfiguration, force: Bool = false) {
        let settings = ProxySettings.shared
        guard settings.isConfigured, force || settings.enabled else { return }
        // iOS has no HTTPS-specific proxy keys (they are macOS-only and
        // marked unavailable in iOS). The HTTP entry alone is enough:
        // URLSession sends HTTPS via HTTP CONNECT through the same proxy.
        config.connectionProxyDictionary = [
            kCFNetworkProxiesHTTPEnable as String: 1,
            kCFNetworkProxiesHTTPProxy as String: "127.0.0.1",
            kCFNetworkProxiesHTTPPort as String: ProxyCore.httpPort,
        ]
    }

    /// Drop-in replacement for `URLSession.shared` at one-shot call sites.
    static var session: URLSession {
        let config = URLSessionConfiguration.default
        apply(to: config)
        return URLSession(configuration: config)
    }

    /// Session for the settings-page connectivity test: always routes via
    /// the core when a node is configured, even if the global toggle is off.
    static var testSession: URLSession {
        let config = URLSessionConfiguration.default
        apply(to: config, force: true)
        return URLSession(configuration: config)
    }

    /// Called from MinisApp.init: bring the core up early when enabled, so
    /// provider sessions created afterwards already find it listening.
    static func startCoreIfEnabled() {
        let settings = ProxySettings.shared
        guard settings.enabled, settings.isConfigured else { return }
        DispatchQueue.global(qos: .utility).async {
            ProxyCore.shared.start()
        }
    }
}
