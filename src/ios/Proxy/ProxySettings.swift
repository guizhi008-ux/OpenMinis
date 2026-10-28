import Foundation
import Combine

/// Proxy node configuration for the built-in Xray core.
///
/// Stored in UserDefaults (this app's house pattern for settings). The
/// values are the user's own node credentials: they never leave the device
/// except inside the proxy connection itself.
enum MinisProxyProtocol: String, CaseIterable, Identifiable {
    case ss
    case vless
    var id: String { rawValue }
    var label: String { self == .ss ? "Shadowsocks" : "VLESS" }
}

final class ProxySettings: ObservableObject {
    static let shared = ProxySettings()

    private let defaults = UserDefaults.standard

    @Published var enabled: Bool {
        didSet { defaults.set(enabled, forKey: "minis.proxy.enabled") }
    }
    @Published var protocolRaw: String {
        didSet { defaults.set(protocolRaw, forKey: "minis.proxy.protocol") }
    }
    @Published var nodeName: String {
        didSet { defaults.set(nodeName, forKey: "minis.proxy.name") }
    }

    // Shadowsocks
    @Published var ssServer: String {
        didSet { defaults.set(ssServer, forKey: "minis.proxy.ss.server") }
    }
    @Published var ssPort: Int {
        didSet { defaults.set(ssPort, forKey: "minis.proxy.ss.port") }
    }
    @Published var ssMethod: String {
        didSet { defaults.set(ssMethod, forKey: "minis.proxy.ss.method") }
    }
    @Published var ssPassword: String {
        didSet { defaults.set(ssPassword, forKey: "minis.proxy.ss.password") }
    }

    // VLESS
    @Published var vlessServer: String {
        didSet { defaults.set(vlessServer, forKey: "minis.proxy.vless.server") }
    }
    @Published var vlessPort: Int {
        didSet { defaults.set(vlessPort, forKey: "minis.proxy.vless.port") }
    }
    @Published var vlessUUID: String {
        didSet { defaults.set(vlessUUID, forKey: "minis.proxy.vless.uuid") }
    }
    @Published var vlessFlow: String {
        didSet { defaults.set(vlessFlow, forKey: "minis.proxy.vless.flow") }
    }
    @Published var vlessSecurity: String {
        didSet { defaults.set(vlessSecurity, forKey: "minis.proxy.vless.security") }
    }
    @Published var vlessSNI: String {
        didSet { defaults.set(vlessSNI, forKey: "minis.proxy.vless.sni") }
    }
    @Published var vlessPublicKey: String {
        didSet { defaults.set(vlessPublicKey, forKey: "minis.proxy.vless.pbk") }
    }
    @Published var vlessShortID: String {
        didSet { defaults.set(vlessShortID, forKey: "minis.proxy.vless.sid") }
    }
    @Published var vlessFingerprint: String {
        didSet { defaults.set(vlessFingerprint, forKey: "minis.proxy.vless.fp") }
    }

    var proto: MinisProxyProtocol {
        get { MinisProxyProtocol(rawValue: protocolRaw) ?? .ss }
        set { protocolRaw = newValue.rawValue }
    }

    init() {
        let d = UserDefaults.standard
        enabled = d.bool(forKey: "minis.proxy.enabled")
        protocolRaw = d.string(forKey: "minis.proxy.protocol") ?? MinisProxyProtocol.ss.rawValue
        nodeName = d.string(forKey: "minis.proxy.name") ?? ""
        ssServer = d.string(forKey: "minis.proxy.ss.server") ?? ""
        ssPort = d.integer(forKey: "minis.proxy.ss.port")
        ssMethod = d.string(forKey: "minis.proxy.ss.method") ?? "aes-256-gcm"
        ssPassword = d.string(forKey: "minis.proxy.ss.password") ?? ""
        vlessServer = d.string(forKey: "minis.proxy.vless.server") ?? ""
        vlessPort = d.integer(forKey: "minis.proxy.vless.port")
        vlessUUID = d.string(forKey: "minis.proxy.vless.uuid") ?? ""
        vlessFlow = d.string(forKey: "minis.proxy.vless.flow") ?? "xtls-rprx-vision"
        vlessSecurity = d.string(forKey: "minis.proxy.vless.security") ?? "reality"
        vlessSNI = d.string(forKey: "minis.proxy.vless.sni") ?? ""
        vlessPublicKey = d.string(forKey: "minis.proxy.vless.pbk") ?? ""
        vlessShortID = d.string(forKey: "minis.proxy.vless.sid") ?? ""
        vlessFingerprint = d.string(forKey: "minis.proxy.vless.fp") ?? "chrome"
    }

    var isConfigured: Bool {
        switch proto {
        case .ss:
            return !ssServer.isEmpty && ssPort > 0 && !ssPassword.isEmpty
        case .vless:
            return !vlessServer.isEmpty && vlessPort > 0 && !vlessUUID.isEmpty
        }
    }

    // MARK: - Share link import

    /// Imports an `ss://` or `vless://` share link. Returns nil on success,
    /// or a user-facing error message.
    func importShareLink(_ raw: String) -> String? {
        let link = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if link.hasPrefix("ss://") {
            return importSS(link)
        }
        if link.hasPrefix("vless://") {
            return importVLESS(link)
        }
        return "只支持 ss:// 或 vless:// 链接"
    }

    private static func base64Decode(_ str: String) -> String? {
        var t = str.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        guard let data = Data(base64Encoded: t) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private static func splitHostPort(_ hostPort: String) -> (String, Int)? {
        guard let idx = hostPort.lastIndex(of: ":") else { return nil }
        let host = String(hostPort[..<idx]).trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard let port = Int(hostPort[hostPort.index(after: idx)...]), port > 0 else { return nil }
        return (host, port)
    }

    private func importSS(_ link: String) -> String? {
        var s = String(link.dropFirst("ss://".count))
        var remark = ""
        if let idx = s.firstIndex(of: "#") {
            remark = String(s[s.index(after: idx)...]).removingPercentEncoding ?? ""
            s = String(s[..<idx])
        }
        if let idx = s.firstIndex(of: "?") {
            s = String(s[..<idx])
        }
        let method: String
        let password: String
        let hostPort: String
        if let atIdx = s.lastIndex(of: "@") {
            // SIP002: ss://base64(method:password)@host:port
            let userinfo = String(s[..<atIdx])
            hostPort = String(s[s.index(after: atIdx)...])
            let creds = Self.base64Decode(userinfo) ?? userinfo
            guard let colon = creds.firstIndex(of: ":") else { return "链接格式不对" }
            method = String(creds[..<colon])
            password = String(creds[creds.index(after: colon)...])
        } else {
            // Legacy: ss://base64(method:password@host:port)
            guard let decoded = Self.base64Decode(s),
                  let atIdx = decoded.lastIndex(of: "@") else { return "链接格式不对" }
            let creds = String(decoded[..<atIdx])
            hostPort = String(decoded[decoded.index(after: atIdx)...])
            guard let colon = creds.firstIndex(of: ":") else { return "链接格式不对" }
            method = String(creds[..<colon])
            password = String(creds[creds.index(after: colon)...])
        }
        guard let (host, port) = Self.splitHostPort(hostPort) else { return "链接里找不到服务器地址或端口" }
        ssMethod = method
        ssPassword = password
        ssServer = host
        ssPort = port
        protocolRaw = MinisProxyProtocol.ss.rawValue
        if !remark.isEmpty { nodeName = remark }
        return nil
    }

    private func importVLESS(_ link: String) -> String? {
        guard let comps = URLComponents(string: link),
              let host = comps.host, !host.isEmpty,
              let uuid = comps.user, !uuid.isEmpty else {
            return "链接格式不对"
        }
        let query = Dictionary(uniqueKeysWithValues: (comps.queryItems ?? []).map { ($0.name, $0.value ?? "") })
        if let type = query["type"], type != "tcp" {
            return "这个节点用的是 \(type) 传输，暂只支持 TCP"
        }
        vlessServer = host
        vlessPort = comps.port ?? 443
        vlessUUID = uuid
        vlessFlow = query["flow"] ?? ""
        vlessSecurity = query["security"] ?? "none"
        vlessSNI = query["sni"] ?? query["peer"] ?? ""
        vlessPublicKey = query["pbk"] ?? ""
        vlessShortID = query["sid"] ?? ""
        vlessFingerprint = query["fp"] ?? "chrome"
        protocolRaw = MinisProxyProtocol.vless.rawValue
        if let remark = comps.fragment, !remark.isEmpty {
            nodeName = remark.removingPercentEncoding ?? remark
        }
        return nil
    }
}
