import Foundation
import Security
import Combine

struct AppProxySavedSettings: Codable {
    var manualType = "http"
    var host = ""
    var port = ""
    var username = ""
    var password = ""
    var subscriptionURL = ""
    var nodes: [AppProxyNode] = []
    var selectedNodeID: String?
    var allowBootstrapDNS = false
}

/// Secrets, URLs and opaque imported outbounds stay in a device-only Keychain
/// item. Only the chosen mode is stored in ordinary preferences.
@MainActor
final class AppProxyStore: ObservableObject {
    static let shared = AppProxyStore()
    @Published var mode = "off"
    @Published var settings = AppProxySavedSettings()
    @Published private(set) var status = "Not connected"
    @Published private(set) var busy = false
    private var restored = false
    private let modeKey = "appProxy.mode"
    private let service = "com.openminis.app.proxy.v1"

    private init() {}

    func restoreBeforeNetworking() {
        guard !restored else { return }
        restored = true
        mode = UserDefaults.standard.string(forKey: modeKey) ?? "off"
        guard ["off", "manual", "subscription"].contains(mode) else {
            blockTraffic(); status = "Saved proxy mode is invalid; traffic is blocked."; return
        }
        do {
            settings = try load()
            try activate()
        } catch {
            if mode == "off" {
                // An inaccessible Keychain must not turn a stored strict policy
                // into a direct route. Off was explicitly stored (or first run).
                try? activate()
            } else { blockTraffic() }
            status = (error as? AppProxyError)?.localizedDescription ?? "Proxy unavailable; traffic is blocked."
        }
    }

    func apply() {
        do {
            // Persist intent before startup: a failed enable never reopens a
            // direct route on the next launch. Failed settings saves block too.
            UserDefaults.standard.set(mode, forKey: modeKey)
            if mode != "off" { blockTraffic() }
            try save()
            try activate()
        } catch {
            if mode != "off" { blockTraffic() }
            status = (error as? AppProxyError)?.localizedDescription ?? "Proxy unavailable; traffic is blocked."
        }
    }

    private func blockTraffic() {
        AppProxyNetwork.activate(AppProxySnapshot())
        AppProxyBridge.stop()
        _ = ISHKernel.shared.configureProxy(withHost: "127.0.0.1", port: 1,
                                            username: "shell", password: "", enabled: true)
    }

    private func activate(mode policyMode: String? = nil, settings policySettings: AppProxySavedSettings? = nil) throws {
        let selectedMode = policyMode ?? mode
        if selectedMode != "off" { blockTraffic() }
        let config = try AppProxyConfiguration.make(mode: selectedMode, settings: policySettings ?? settings)
        let snapshot = try AppProxyBridge.configure(config)
        let result = ISHKernel.shared.configureProxy(withHost: "127.0.0.1", port: UInt16(snapshot.port),
                                                      username: "shell", password: snapshot.password,
                                                      enabled: snapshot.enabled)
        guard result == 0 else { throw AppProxyError.unavailable }
        AppProxyNetwork.activate(snapshot)
        status = snapshot.enabled ? "Connected · strict routing" : "Off · direct app connections"
    }

    /// Synchronous gate at foreground entry, before lifecycle network work.
    func checkOnForeground() {
        let savedMode = UserDefaults.standard.string(forKey: modeKey) ?? "off"
        guard restored, savedMode != "off" else { return }
        if !AppProxyBridge.isRunning() || !AppProxyNetwork.snapshot.ready {
            // Draft form edits are not an applied policy. Restore the saved
            // transaction rather than silently activating unsaved controls.
            do { try activate(mode: savedMode, settings: load()) }
            catch { blockTraffic(); status = "Proxy unavailable; traffic is blocked. Reconnect in settings." }
        }
    }

    func importText(_ text: String) {
        do {
            let result = try AppProxyBridge.importNodes(text)
            guard !result.nodes.isEmpty else { status = "No supported nodes found. Existing nodes were kept."; return }
            let previous = settings
            settings.nodes = result.nodes
            if !result.nodes.contains(where: { $0.id == settings.selectedNodeID }) { settings.selectedNodeID = nil }
            do { try save() } catch { settings = previous; throw error }
            // A removed active node must not retain a hidden working route.
            if mode == "subscription" && settings.selectedNodeID == nil { blockTraffic() }
            status = "Imported \(result.nodes.count) nodes; \(result.issues) unsupported or invalid entries. Choose a node and Connect."
        } catch { status = "Import failed. Existing nodes were kept." }
    }

    func removeNodes(at offsets: IndexSet) {
        let removedIDs = offsets.map { settings.nodes[$0].id }
        let previous = settings
        for index in offsets.sorted(by: >) { settings.nodes.remove(at: index) }
        if let id = settings.selectedNodeID, removedIDs.contains(id) {
            settings.selectedNodeID = nil
            if mode == "subscription" { blockTraffic() }
        }
        do { try save(); status = "Nodes removed. Choose a node and Connect." }
        catch { settings = previous; status = "Could not save node changes." }
    }

    func updateSubscription() async {
        guard !busy else { return }
        guard let url = URL(string: settings.subscriptionURL), url.scheme?.lowercased() == "https", url.host != nil else {
            status = "Enter an HTTPS subscription URL, or import offline text."; return
        }
        // No direct bootstrap download. With Off/unready, offline import is
        // available; the user must first connect a manual/working node.
        guard AppProxyNetwork.snapshot.enabled, AppProxyNetwork.snapshot.ready else {
            status = "Connect a proxy first to download subscriptions, or import offline text. No direct download was made."; return
        }
        busy = true
        defer { busy = false }
        do {
            var request = URLRequest(url: url)
            request.timeoutInterval = 30
            let session = AppProxyNetwork.makeSession(configuration: .ephemeral,
                                                       delegate: ProxySubscriptionRedirectPolicy())
            defer { session.invalidateAndCancel() }
            let (bytes, response) = try await session.bytes(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw AppProxyError.unavailable }
            var data = Data()
            for try await byte in bytes {
                guard data.count < 4 * 1024 * 1024 else { throw AppProxyError.invalidConfiguration }
                data.append(byte)
            }
            guard let text = String(data: data, encoding: .utf8) else { throw AppProxyError.invalidResponse }
            importText(text)
        } catch { status = "Subscription update failed. Existing nodes were kept." }
    }

    func testConnection() async {
        guard !busy, AppProxyNetwork.snapshot.enabled, AppProxyNetwork.snapshot.ready else {
            status = "Connect a proxy before testing."; return
        }
        busy = true
        defer { busy = false }
        let started = Date()
        do {
            var request = URLRequest(url: URL(string: "https://www.apple.com/library/test/success.html")!)
            request.timeoutInterval = 15
            request.cachePolicy = .reloadIgnoringLocalCacheData
            let (_, response) = try await AppProxyNetwork.shared.data(for: request)
            guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw AppProxyError.unavailable }
            let milliseconds = Int(Date().timeIntervalSince(started) * 1000)
            status = "HTTPS connection succeeded through the selected proxy · \(milliseconds) ms."
        } catch { status = "Connection test failed. No direct fallback was used." }
    }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
         kSecAttrAccount as String: "settings", kSecAttrSynchronizable as String: false]
    }
    private func load() throws -> AppProxySavedSettings {
        var q = query
        q[kSecReturnData as String] = true
        var value: CFTypeRef?
        let result = SecItemCopyMatching(q as CFDictionary, &value)
        if result == errSecItemNotFound { return AppProxySavedSettings() }
        guard result == errSecSuccess, let data = value as? Data else { throw AppProxyError.keychain }
        do { return try JSONDecoder().decode(AppProxySavedSettings.self, from: data) }
        catch { throw AppProxyError.keychain }
    }
    private func save() throws {
        let data = try JSONEncoder().encode(settings)
        let attributes: [String: Any] = [kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let result = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if result == errSecItemNotFound {
            var q = query
            attributes.forEach { q[$0.key] = $0.value }
            guard SecItemAdd(q as CFDictionary, nil) == errSecSuccess else { throw AppProxyError.keychain }
        } else if result != errSecSuccess { throw AppProxyError.keychain }
    }
}


/// Subscription secrets must not be redirected to plaintext HTTP.
private final class ProxySubscriptionRedirectPolicy: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest,
                    completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(request.url?.scheme?.lowercased() == "https" ? request : nil)
    }
}


enum AppProxyConfiguration {
    static func make(mode: String, settings: AppProxySavedSettings) throws -> [String: Any] {
        guard ["off", "manual", "subscription"].contains(mode) else { throw AppProxyError.invalidConfiguration }
        var config: [String: Any] = ["mode": mode == "subscription" ? "node" : mode,
                                    "allowBootstrapDNS": settings.allowBootstrapDNS]
        if mode == "manual" {
            guard let port = Int(settings.port), (1...65535).contains(port),
                  !settings.host.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw AppProxyError.invalidConfiguration
            }
            config["manual"] = ["type": settings.manualType, "host": settings.host,
                                "port": port, "username": settings.username, "password": settings.password]
        } else if mode == "subscription" {
            guard let node = settings.nodes.first(where: { $0.id == settings.selectedNodeID }) else {
                throw AppProxyError.missingNode
            }
            config["node"] = node.dictionary
        }
        return config
    }
}
