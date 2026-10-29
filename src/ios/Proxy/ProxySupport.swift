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
        if settings.autoMode, !force {
            ensureCoreRunning()
        }
        noteUse()
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

    // MARK: - Guest (embedded Linux environment) proxy

    private static let guestEnvKeys = ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"]
    private static let guestEnvFlag = "minis.proxy.guestEnvManaged"

    /// The device's current LAN IPv4 (Wi-Fi first, then cellular). The
    /// guest's loopback is isolated from the host's, but its traffic is
    /// NATed onto the device's real interfaces, so it can reach a listener
    /// bound to the interface address.
    static func lanIPv4() -> String? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(first) }
        var wifi: String?
        var cellular: String?
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let current = cursor {
            defer { cursor = current.pointee.ifa_next }
            // IFF_UP 0x1, IFF_LOOPBACK 0x8, IFF_RUNNING 0x40
            let flags = Int32(current.pointee.ifa_flags)
            guard let addr = current.pointee.ifa_addr,
                  addr.pointee.sa_family == UInt8(AF_INET),
                  flags & 0x1 != 0, flags & 0x40 != 0, flags & 0x8 == 0
            else { continue }
            let name = String(cString: current.pointee.ifa_name)
            var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            getnameinfo(addr, socklen_t(addr.pointee.sa_len), &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST)
            let ip = String(cString: buf)
            if name == "en0" { wifi = ip }
            if name.hasPrefix("pdp_ip") { cellular = ip }
        }
        return wifi ?? cellular
    }

    /// Proxy URL the guest environment should use right now, or nil when
    /// the core is not running or no LAN address is available.
    static func guestProxyURL() -> String? {
        let settings = ProxySettings.shared
        guard settings.enabled, ProxyCore.shared.isRunning, let ip = lanIPv4() else { return nil }
        return "http://minis:\(settings.lanSecret)@\(ip):\(ProxyCore.lanHTTPPort)"
    }

    /// Keeps the guest environment's proxy variables in sync with the core:
    /// points http_proxy/https_proxy at the LAN inbound while the core is
    /// up, removes them when it stops. Only touches variables this feature
    /// manages (tracked via a flag + the port marker in the value).
    static func syncGuestProxyEnv() {
        DispatchQueue.main.async {
            let store = EnvVarStore.shared
            let defaults = UserDefaults.standard
            let managed = defaults.bool(forKey: guestEnvFlag)
            let marker = ":\(ProxyCore.lanHTTPPort)"
            if let url = guestProxyURL() {
                for key in guestEnvKeys {
                    if let entry = store.entries.first(where: { $0.key == key }) {
                        if managed || (store.allAsDict()[key]?.contains(marker) ?? false) {
                            store.update(id: entry.id, key: key, value: url)
                        }
                    } else {
                        store.add(key: key, value: url, note: "Minis 代理自动管理（Linux 小系统走代理）")
                    }
                }
                defaults.set(true, forKey: guestEnvFlag)
            } else if managed {
                for key in guestEnvKeys {
                    if let entry = store.entries.first(where: { $0.key == key }),
                       store.allAsDict()[key]?.contains(marker) ?? false {
                        store.delete(id: entry.id)
                    }
                }
                defaults.set(false, forKey: guestEnvFlag)
            }
        }
    }

    /// Called from MinisApp.init: bring the core up early when enabled, so
    /// provider sessions created afterwards already find it listening.
    /// In smart on-demand mode the core stays off until first use; only
    /// the idle watchdog is armed here.
    static func startCoreIfEnabled() {
        let settings = ProxySettings.shared
        // Reconcile: in on-demand mode the master switch is forced on.
        if settings.autoMode, !settings.enabled {
            settings.enabled = true
        }
        guard settings.enabled, settings.isConfigured else { return }
        startIdleWatchdog()
        guard !settings.autoMode else { return }
        DispatchQueue.global(qos: .utility).async {
            ProxyCore.shared.start()
        }
    }

    // MARK: - Smart on-demand

    /// Idle window after which an unused core is stopped in auto mode.
    static let autoIdleSeconds: TimeInterval = 600
    private static var lastUse = Date.distantPast
    private static let useLock = NSLock()
    private static var watchdogStarted = false
    private static var startInFlight = false

    static func noteUse() {
        useLock.lock()
        lastUse = Date()
        useLock.unlock()
    }

    /// Guest shells count as use when their environment carries our
    /// injected proxy variables.
    static func noteGuestActivity(env: [String: String]) {
        let marker = ":\(ProxyCore.lanHTTPPort)"
        if let v = env["http_proxy"] ?? env["https_proxy"], v.contains(marker) {
            noteUse()
            if ProxySettings.shared.autoMode {
                ensureCoreRunning()
            }
        }
    }

    /// Starts the core if it is not already running (auto mode's lazy
    /// start). Waits briefly so the session being configured does not
    /// race the listener coming up.
    static func ensureCoreRunning() {
        let settings = ProxySettings.shared
        guard settings.enabled, settings.isConfigured else { return }
        guard !ProxyCore.shared.isRunning else { return }
        useLock.lock()
        if startInFlight {
            useLock.unlock()
            return
        }
        startInFlight = true
        useLock.unlock()
        let sem = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .userInitiated).async {
            ProxyCore.shared.start()
            useLock.lock()
            startInFlight = false
            useLock.unlock()
            sem.signal()
        }
        _ = sem.wait(timeout: .now() + 3)
        noteUse()
    }

    /// Periodically stops an idle core in auto mode.
    static func startIdleWatchdog() {
        useLock.lock()
        if watchdogStarted {
            useLock.unlock()
            return
        }
        watchdogStarted = true
        useLock.unlock()
        DispatchQueue.global(qos: .utility).async {
            while true {
                Thread.sleep(forTimeInterval: 60)
                let settings = ProxySettings.shared
                guard settings.autoMode, settings.enabled, ProxyCore.shared.isRunning else { continue }
                useLock.lock()
                let idle = Date().timeIntervalSince(lastUse)
                useLock.unlock()
                if idle > autoIdleSeconds {
                    ProxyCore.shared.stop()
                }
            }
        }
    }
}
