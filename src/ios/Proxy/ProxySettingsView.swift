import SwiftUI

/// Settings › Proxy — configures the built-in Xray core so this app's own
/// provider traffic can go through the user's SS / VLESS node, the way
/// Telegram lets you set a proxy in-app. App-only: no system VPN, and the
/// Linux sandbox keeps its own direct networking.
struct ProxySettingsView: View {
    @ObservedObject private var settings = ProxySettings.shared
    @State private var linkText: String = ""
    @State private var importMessage: String?
    @State private var statusTick: Int = 0
    @State private var testResult: String?

    private var coreRunning: Bool {
        _ = statusTick
        return ProxyCore.shared.isRunning
    }

    var body: some View {
        Form {
            Section {
                Toggle("启用代理", isOn: $settings.enabled)
                Picker("协议", selection: $settings.protocolRaw) {
                    ForEach(MinisProxyProtocol.allCases) { proto in
                        Text(proto.label).tag(proto.rawValue)
                    }
                }
                .pickerStyle(.segmented)
            } header: {
                Text("代理")
            } footer: {
                Text("开启后，本应用访问各模型接口的流量走下面的节点；关闭则全部直连。只影响本应用，不影响其他应用和系统。")
            }

            Section {
                Picker("路由模式", selection: $settings.routingMode) {
                    Text("配置分流").tag("config")
                    Text("全局代理").tag("global")
                }
                .pickerStyle(.segmented)
                if settings.routingMode == "config" {
                    Text("强制直连域名（每行一个，如 example.cn）")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $settings.directDomainsText)
                        .frame(height: 72)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    Text("强制走代理域名（每行一个，如 example.com）")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    TextEditor(text: $settings.proxyDomainsText)
                        .frame(height: 72)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                }
            } header: {
                Text("路由")
            } footer: {
                Text(settings.routingMode == "config"
                    ? "配置分流：国内网站和国内 IP 直连，其余走代理，和小火箭的「配置」模式一致；上面两个名单优先于内置规则。改完记得重启内核。"
                    : "全局代理：除局域网地址外，全部流量走代理。改完记得重启内核。")
            }

            Section {
                TextField("粘贴 ss:// 或 vless:// 节点链接", text: $linkText)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                Button("导入链接") {
                    if let error = settings.importShareLink(linkText) {
                        importMessage = error
                    } else {
                        importMessage = "导入成功"
                        linkText = ""
                    }
                }
                if let importMessage {
                    Text(importMessage)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("从链接导入")
            }

            if settings.proto == .ss {
                Section {
                    TextField("服务器地址", text: $settings.ssServer)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    TextField("端口", value: $settings.ssPort, format: .number)
                        .keyboardType(.numberPad)
                    Picker("加密方式", selection: $settings.ssMethod) {
                        Text("aes-256-gcm").tag("aes-256-gcm")
                        Text("aes-128-gcm").tag("aes-128-gcm")
                        Text("chacha20-ietf-poly1305").tag("chacha20-ietf-poly1305")
                        Text("2022-blake3-aes-256-gcm").tag("2022-blake3-aes-256-gcm")
                    }
                    SecureField("密码", text: $settings.ssPassword)
                } header: {
                    Text("Shadowsocks 节点")
                }
            } else {
                Section {
                    TextField("服务器地址", text: $settings.vlessServer)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    TextField("端口", value: $settings.vlessPort, format: .number)
                        .keyboardType(.numberPad)
                    TextField("UUID", text: $settings.vlessUUID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    TextField("流控 flow（可空）", text: $settings.vlessFlow)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    Picker("安全层", selection: $settings.vlessSecurity) {
                        Text("Reality").tag("reality")
                        Text("TLS").tag("tls")
                        Text("无").tag("none")
                    }
                    TextField("SNI 域名", text: $settings.vlessSNI)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    TextField("Reality 公钥 pbk", text: $settings.vlessPublicKey)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    TextField("Reality ShortId（可空）", text: $settings.vlessShortID)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled(true)
                    Picker("指纹 fingerprint", selection: $settings.vlessFingerprint) {
                        Text("chrome").tag("chrome")
                        Text("safari").tag("safari")
                        Text("ios").tag("ios")
                        Text("firefox").tag("firefox")
                    }
                } header: {
                    Text("VLESS 节点（仅 TCP 传输）")
                }
            }

            Section {
                HStack {
                    Text("内核状态")
                    Spacer()
                    Text(coreRunning ? "运行中" : "未运行")
                        .foregroundStyle(coreRunning ? .green : .secondary)
                }
                if !ProxyCore.shared.lastError.isEmpty {
                    Text(ProxyCore.shared.lastError)
                        .font(.caption)
                        .foregroundStyle(.red)
                }
                Button("启动 / 重启内核") {
                    DispatchQueue.global(qos: .userInitiated).async {
                        ProxyCore.shared.restart()
                        DispatchQueue.main.async { statusTick += 1 }
                    }
                }
                Button("停止内核") {
                    ProxyCore.shared.stop()
                    statusTick += 1
                }
                Button("测试连通性") {
                    runTest()
                }
                if let testResult {
                    Text(testResult)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text("内核")
            } footer: {
                Text("改完节点信息后点一次「启动 / 重启内核」。已经打开的对话若不生效，重开一次应用。测试会通过节点访问一个谷歌的连通性地址。")
            }
        }
        .navigationTitle("代理")
        .onAppear { statusTick += 1 }
    }

    private func runTest() {
        testResult = "测试中…"
        Task {
            var request = URLRequest(url: URL(string: "https://www.gstatic.com/generate_204")!)
            request.timeoutInterval = 15
            do {
                let (_, response) = try await ProxySupport.testSession.data(for: request)
                let code = (response as? HTTPURLResponse)?.statusCode ?? -1
                testResult = (code == 204 || code == 200) ? "连通（HTTP \(code)）" : "异常（HTTP \(code)）"
            } catch {
                testResult = "失败：\(error.localizedDescription)"
            }
            statusTick += 1
        }
    }
}
