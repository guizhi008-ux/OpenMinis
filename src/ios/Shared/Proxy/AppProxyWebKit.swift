import Foundation
import Network
import WebKit

/// All creation sites, including supplied window.open configurations, pass
/// through this boundary before a web view can start a network request.
enum AppProxyWebKit {
    private static let stores = NSHashTable<WKWebsiteDataStore>.weakObjects()
    private static let views = NSHashTable<WKWebView>.weakObjects()
    private static var observer: NSObjectProtocol?

    static func prepare(_ configuration: WKWebViewConfiguration) {
        precondition(Thread.isMainThread)
        observeChanges()
        let store = configuration.websiteDataStore
        stores.add(store)
        configure(store, snapshot: AppProxyNetwork.snapshot)
    }

    static func register(_ webView: WKWebView) {
        precondition(Thread.isMainThread)
        views.add(webView)
    }

    private static func configure(_ store: WKWebsiteDataStore, snapshot: AppProxySnapshot) {
        // WKWebsiteDataStore proxy configurations require iOS 17; older
        // systems expose no per-store proxy API, so there is nothing to set.
        if #available(iOS 17.0, *) {
            guard snapshot.enabled else { store.proxyConfigurations = []; return }
            let port = snapshot.ready ? snapshot.httpPort : 1
            let endpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(clamping: port))!)
            var proxy = ProxyConfiguration(httpCONNECTProxy: endpoint, tlsOptions: nil)
            proxy.applyCredential(username: snapshot.username, password: snapshot.password)
            proxy.allowFailover = false
            proxy.matchDomains = [""]
            proxy.excludedDomains = ["localhost", "127.0.0.1", "::1"]
            store.proxyConfigurations = [proxy]
        }
    }

    private static func observeChanges() {
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(forName: .appProxyDidChange,
                                                          object: nil, queue: .main) { _ in
            let snapshot = AppProxyNetwork.snapshot
            // Update all stores before another page can load. Stop the old
            // document as well: its JS/WebSockets must not retain the old exit.
            for store in stores.allObjects { configure(store, snapshot: snapshot) }
            for view in views.allObjects {
                view.stopLoading()
                view.loadHTMLString("<meta name='viewport' content='width=device-width'><p>Network proxy changed. Reload the page to continue.</p>", baseURL: nil)
            }
        }
    }
}
