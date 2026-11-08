import Foundation
import Network

/// A value copy is used for every new session. Before restoration, networking is
/// blocked: property initializers must not open a direct session during launch.
struct AppProxySnapshot: Sendable {
    var enabled = true
    var ready = false
    var port = 0
    var httpPort = 0
    var password = ""
    var username = "default"
}

extension Notification.Name {
    static let appProxyDidChange = Notification.Name("appProxyDidChange")
}

enum AppProxyNetwork {
    private static let lock = NSRecursiveLock()
    private static var active = AppProxySnapshot()
    private static var generation: UInt64 = 0
    private static var sessions: [WeakSession] = []
    private static var sharedSession: URLSession?
    private static var cachedSessions: [String: URLSession] = [:]
    private final class WeakSession {
        weak var value: URLSession?
        init(_ value: URLSession) { self.value = value }
    }

    static var snapshot: AppProxySnapshot {
        lock.lock(); defer { lock.unlock() }
        return active
    }
    static var strictEnabled: Bool { snapshot.enabled }
    static var sessionGeneration: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return generation
    }

    /// Cancels old requests before publishing a different route. Clients holding
    /// an old SDK session fail until recreated; they can never resume directly.
    static func activate(_ snapshot: AppProxySnapshot) {
        lock.lock()
        let previous = sessions.compactMap(\.value)
        sessions.removeAll()
        sharedSession = nil
        cachedSessions.removeAll()
        active = snapshot
        generation &+= 1
        previous.forEach { $0.invalidateAndCancel() }
        lock.unlock()
        NotificationCenter.default.post(name: .appProxyDidChange, object: nil)
    }

    static var shared: URLSession {
        lock.lock(); defer { lock.unlock() }
        if let session = sharedSession { return session }
        let session = makeSession(configuration: .default)
        sharedSession = session
        return session
    }

    static func cachedSession(key: String, configuration: URLSessionConfiguration) -> URLSession {
        lock.lock(); defer { lock.unlock() }
        if let session = cachedSessions[key] { return session }
        let session = makeSession(configuration: configuration)
        cachedSessions[key] = session
        return session
    }

    static func releaseCachedSession(key: String) {
        lock.lock()
        let session = cachedSessions.removeValue(forKey: key)
        lock.unlock()
        session?.invalidateAndCancel()
    }

    static func configure(_ config: URLSessionConfiguration) -> URLSessionConfiguration {
        lock.lock(); defer { lock.unlock() }
        return configure(config, snapshot: active)
    }

    private static func configure(_ config: URLSessionConfiguration, snapshot: AppProxySnapshot) -> URLSessionConfiguration {
        let result = config.copy() as! URLSessionConfiguration
        guard snapshot.enabled else { return result }
        // A URLProtocol actively rejects requests before any connection/DNS.
        // It is prepended so SDK URLProtocols cannot bypass an unready route.
        if !snapshot.ready {
            result.protocolClasses = [AppProxyBlockedProtocol.self] + (result.protocolClasses ?? [])
        }
        // Also block non-URLProtocol paths (including WebSocket tasks) at a
        // dead loopback proxy. Never leave an absent upstream as "no proxy".
        let port = snapshot.ready ? snapshot.httpPort : 1
        let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(port))!)
        var proxy = ProxyConfiguration(httpCONNECTProxy: endpoint, tlsOptions: nil)
        proxy.applyCredential(username: snapshot.username, password: snapshot.password)
        proxy.allowFailover = false
        proxy.matchDomains = [""]
        proxy.excludedDomains = ["localhost", "127.0.0.1", "::1"]
        result.proxyConfigurations = [proxy]
        return result
    }

    static func makeSession(configuration: URLSessionConfiguration,
                            delegate: URLSessionDelegate? = nil,
                            delegateQueue: OperationQueue? = nil) -> URLSession {
        lock.lock(); defer { lock.unlock() }
        let session = URLSession(configuration: configure(configuration, snapshot: active),
                                 delegate: delegate, delegateQueue: delegateQueue)
        sessions.removeAll { $0.value == nil }
        sessions.append(WeakSession(session))
        return session
    }
}

private final class AppProxyBlockedProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool {
        !["localhost", "127.0.0.1", "::1", "[::1]"].contains(request.url?.host?.lowercased() ?? "")
    }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet,
            userInfo: [NSLocalizedDescriptionKey: "App proxy is unavailable. Check Network Proxy settings."]))
    }
    override func stopLoading() {}
}
