import XCTest
import WebKit
import Network
@testable import Minis

final class AppProxyWebKitTests: XCTestCase {
    override func tearDown() {
        AppProxyNetwork.activate(AppProxySnapshot(enabled: false, ready: true))
        super.tearDown()
    }

    @MainActor
    func testStrictWebStoreHasNoDirectFailover() {
        AppProxyNetwork.activate(AppProxySnapshot(enabled: true, ready: true, port: 1080,
                                                 httpPort: 8080, password: "process-secret"))
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        AppProxyWebKit.prepare(config)
        XCTAssertEqual(config.websiteDataStore.proxyConfigurations.count, 1)
        XCTAssertFalse(config.websiteDataStore.proxyConfigurations[0].allowFailover)
    }

    @MainActor
    func testUnavailableStrictRouteStillInstallsProxy() {
        AppProxyNetwork.activate(AppProxySnapshot())
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        AppProxyWebKit.prepare(config)
        XCTAssertEqual(config.websiteDataStore.proxyConfigurations.count, 1)
        XCTAssertFalse(config.websiteDataStore.proxyConfigurations[0].allowFailover)
    }

    @MainActor
    func testOffModeRemovesAppProxyFromRegisteredStore() {
        AppProxyNetwork.activate(AppProxySnapshot())
        let config = WKWebViewConfiguration()
        config.websiteDataStore = .nonPersistent()
        AppProxyWebKit.prepare(config)
        AppProxyNetwork.activate(AppProxySnapshot(enabled: false, ready: true))
        XCTAssertTrue(config.websiteDataStore.proxyConfigurations.isEmpty)
    }
}
