import XCTest
@testable import Minis

/// These tests exercise real Foundation sessions, cancellation and URLProtocol
/// dispatch. They require the iOS test target; source inspection is not a test.
final class AppProxyNetworkTests: XCTestCase {
    override func tearDown() {
        AppProxyNetwork.activate(AppProxySnapshot(enabled: false, ready: true))
        super.tearDown()
    }

    func testUnavailableCoreRejectsBeforeAnSDKProtocolCanRun() async {
        AppProxyNetwork.activate(AppProxySnapshot())
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ProxyTestProtocol.self]
        let session = AppProxyNetwork.makeSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        do {
            _ = try await session.data(from: URL(string: "https://unreachable.invalid/test")!)
            XCTFail("An unavailable proxy must reject the request")
        } catch {
            XCTAssertEqual((error as? URLError)?.code, .notConnectedToInternet)
        }
    }

    func testFactoryCopiesConfigurationAndPreservesStreamingOptions() {
        AppProxyNetwork.activate(AppProxySnapshot(enabled: true, ready: true, port: 18880,
                                                httpPort: 18881, password: "test-secret", username: "default"))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 600
        configuration.timeoutIntervalForResource = 900
        configuration.protocolClasses = [ProxyTestProtocol.self]
        configuration.httpShouldSetCookies = false
        let configured = AppProxyNetwork.configure(configuration)
        XCTAssertFalse(configured === configuration)
        XCTAssertTrue(configuration.proxyConfigurations.isEmpty)
        XCTAssertEqual(configured.timeoutIntervalForRequest, 600)
        XCTAssertEqual(configured.timeoutIntervalForResource, 900)
        XCTAssertEqual(configured.httpShouldSetCookies, false)
        XCTAssertTrue(configured.protocolClasses?.first == ProxyTestProtocol.self)
        XCTAssertEqual(configured.proxyConfigurations.count, 1)
        XCTAssertFalse(configured.proxyConfigurations[0].allowFailover)
        XCTAssertEqual(configured.proxyConfigurations[0].matchDomains, [""])
        XCTAssertEqual(configured.proxyConfigurations[0].excludedDomains, ["localhost", "127.0.0.1", "::1"])
    }

    func testSwitchCancelsOldInFlightTaskAndRebuildsCachedSession() async {
        AppProxyNetwork.activate(AppProxySnapshot(enabled: false, ready: true))
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ProxyHangingProtocol.self]
        let old = AppProxyNetwork.cachedSession(key: "test-switch", configuration: configuration)
        let started = expectation(description: "old task entered URLProtocol")
        ProxyHangingProtocol.started = { started.fulfill() }
        let cancelled = expectation(description: "old task was cancelled")
        let task = old.dataTask(with: URL(string: "https://unreachable.invalid/test")!) { _, _, error in
            XCTAssertEqual((error as? URLError)?.code, .cancelled)
            cancelled.fulfill()
        }
        task.resume()
        await fulfillment(of: [started], timeout: 2)
        AppProxyNetwork.activate(AppProxySnapshot())
        let replacement = AppProxyNetwork.cachedSession(key: "test-switch", configuration: configuration)
        XCTAssertFalse(replacement === old)
        XCTAssertTrue(AppProxyNetwork.strictEnabled)
        XCTAssertFalse(AppProxyNetwork.snapshot.ready)
        await fulfillment(of: [cancelled], timeout: 2)
        ProxyHangingProtocol.started = nil
    }

    func testStoredStrictModesCannotProduceAnOffConfigurationWhenIncomplete() throws {
        let settings = AppProxySavedSettings()
        XCTAssertThrowsError(try AppProxyConfiguration.make(mode: "manual", settings: settings))
        XCTAssertThrowsError(try AppProxyConfiguration.make(mode: "subscription", settings: settings))
        XCTAssertThrowsError(try AppProxyConfiguration.make(mode: "unknown", settings: settings))
        XCTAssertEqual(try AppProxyConfiguration.make(mode: "off", settings: settings)["mode"] as? String, "off")
    }

    func testManualValidationAndBootstrapConsentArePreserved() throws {
        var settings = AppProxySavedSettings()
        settings.host = "proxy.invalid"
        settings.port = "65536"
        XCTAssertThrowsError(try AppProxyConfiguration.make(mode: "manual", settings: settings))
        settings.port = "1080"
        let config = try AppProxyConfiguration.make(mode: "manual", settings: settings)
        XCTAssertEqual(config["mode"] as? String, "manual")
        XCTAssertEqual(config["allowBootstrapDNS"] as? Bool, false)
        settings.allowBootstrapDNS = true
        XCTAssertEqual(try AppProxyConfiguration.make(mode: "manual", settings: settings)["allowBootstrapDNS"] as? Bool, true)
    }

    func testOpaqueNodeParametersRoundTripWithoutDiscardingSecretsOrOptions() throws {
        let payload = Data(#"[{"id":"1","name":"node","type":"vless","outbound":{"type":"vless","server":"example.invalid","server_port":443,"uuid":"secret","tls":{"enabled":true,"server_name":"sni.invalid"},"transport":{"type":"ws","path":"/a%2Fb?x=1"}}}]"#.utf8)
        let nodes = try JSONDecoder().decode([AppProxyNode].self, from: payload)
        let encoded = try JSONEncoder().encode(nodes)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: encoded) as? NSArray,
                       try JSONSerialization.jsonObject(with: payload) as? NSArray)
    }
}

private final class ProxyTestProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        client?.urlProtocol(self, didFailWithError: URLError(.unsupportedURL))
    }
    override func stopLoading() {}
}
private final class ProxyHangingProtocol: URLProtocol {
    static var started: (() -> Void)?
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() { Self.started?() }
    override func stopLoading() {}
}
