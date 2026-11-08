import Foundation
import Darwin

/// Only sanitized errors supplied by the core cross the UI boundary. Never
/// include input JSON, URLs, imported nodes or credentials in diagnostics.
enum AppProxyError: LocalizedError {
    case unavailable, invalidResponse, invalidConfiguration, keychain, missingNode
    var errorDescription: String? {
        switch self {
        case .unavailable: return "The app proxy could not start. Traffic remains blocked."
        case .invalidResponse: return "The proxy core returned an invalid response."
        case .invalidConfiguration: return "Check the proxy address, port and credentials."
        case .keychain: return "Proxy settings could not be read or saved securely. Unlock the device and try again."
        case .missingNode: return "Choose a proxy node before connecting."
        }
    }
}

enum AppProxyBridge {
    private static func decode(_ pointer: UnsafeMutablePointer<CChar>?) throws -> [String: Any] {
        guard let pointer else { throw AppProxyError.unavailable }
        defer { MinisAppProxyFreeString(pointer) }
        guard let data = String(cString: pointer).data(using: .utf8),
              let envelope = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              envelope["ok"] as? Bool == true,
              let value = envelope["data"] as? [String: Any] else { throw AppProxyError.unavailable }
        return value
    }
    private static func call(_ text: String,
                             function: (UnsafeMutablePointer<CChar>) -> UnsafeMutablePointer<CChar>?) throws -> [String: Any] {
        guard !text.utf8.contains(0), let input = strdup(text) else { throw AppProxyError.invalidConfiguration }
        defer { free(input) }
        return try decode(function(input))
    }
    static func configure(_ value: [String: Any]) throws -> AppProxySnapshot {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys])
        let result = try call(String(decoding: data, as: UTF8.self)) { MinisAppProxyConfigure($0) }
        if value["mode"] as? String == "off" { return AppProxySnapshot(enabled: false, ready: true) }
        guard let port = result["port"] as? Int, let httpPort = result["httpPort"] as? Int,
              (1...65535).contains(port), (1...65535).contains(httpPort),
              let password = result["password"] as? String, !password.isEmpty else { throw AppProxyError.invalidResponse }
        return AppProxySnapshot(enabled: true, ready: true, port: port, httpPort: httpPort,
                                password: password, username: result["username"] as? String ?? "default")
    }
    static func importNodes(_ text: String) throws -> (nodes: [AppProxyNode], issues: Int) {
        let result = try call(text) { MinisAppProxyImport($0) }
        guard let nodes = result["nodes"] as? [[String: Any]] else { throw AppProxyError.invalidResponse }
        let data = try JSONSerialization.data(withJSONObject: nodes)
        return (try JSONDecoder().decode([AppProxyNode].self, from: data), (result["issues"] as? [Any])?.count ?? 0)
    }
    static func stop() {
        if let pointer = MinisAppProxyStop() { MinisAppProxyFreeString(pointer) }
    }
    static func isRunning() -> Bool {
        guard let status = try? decode(MinisAppProxyStatus()) else { return false }
        return status["running"] as? Bool ?? status["ready"] as? Bool ?? false
    }
}

/// JSON values are retained through Codable, including protocol
/// options unknown to Swift. Only the core decides whether a node is supported.
struct AppProxyNode: Identifiable, Codable, Hashable {
    var id: String
    var name: String
    var type: String
    var outbound: [String: ProxyJSON]
    var dictionary: [String: Any] {
        ["id": id, "name": name, "type": type, "outbound": outbound.mapValues(\.value)]
    }
}
indirect enum ProxyJSON: Codable, Hashable {
    case string(String), number(Double), bool(Bool), object([String: ProxyJSON]), array([ProxyJSON]), null
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let v = try? c.decode(Bool.self) { self = .bool(v) }
        else if let v = try? c.decode(String.self) { self = .string(v) }
        else if let v = try? c.decode(Double.self) { self = .number(v) }
        else if let v = try? c.decode([String: ProxyJSON].self) { self = .object(v) }
        else { self = .array(try c.decode([ProxyJSON].self)) }
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .bool(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .null: try c.encodeNil()
        }
    }
    var value: Any {
        switch self {
        case .string(let v): return v
        case .number(let v): return v
        case .bool(let v): return v
        case .object(let v): return v.mapValues(\.value)
        case .array(let v): return v.map(\.value)
        case .null: return NSNull()
        }
    }
}
