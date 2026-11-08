import SwiftUI

struct NetworkProxySettingsView: View {
    @ObservedObject private var store = AppProxyStore.shared
    @State private var importText = ""
    @State private var showImport = false

    var body: some View {
        Form {
            Section {
                Picker("Mode", selection: $store.mode) {
                    Text("Off").tag("off")
                    Text("Manual Proxy").tag("manual")
                    Text("Subscription Node").tag("subscription")
                }
                Text(store.status).font(.footnote).foregroundStyle(.secondary)
            } footer: {
                Text("Changes take effect when you Connect or Apply. Enabling a proxy uses strict routing: unavailable routes block requests and never fall back to direct connections. Only OpenMinis is affected.")
            }
            if store.mode == "manual" {
                Section("Manual Proxy") {
                    Picker("Protocol", selection: $store.settings.manualType) {
                        Text("HTTP CONNECT").tag("http")
                        Text("HTTPS CONNECT").tag("https")
                        Text("SOCKS5").tag("socks5")
                    }
                    TextField("Server address", text: $store.settings.host)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    TextField("Port", text: $store.settings.port).keyboardType(.numberPad)
                    TextField("Username (optional)", text: $store.settings.username)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    SecureField("Password (optional)", text: $store.settings.password)
                }
            }
            if store.mode == "subscription" {
                Section {
                    TextField("HTTPS subscription URL", text: $store.settings.subscriptionURL)
                        .textInputAutocapitalization(.never).autocorrectionDisabled().keyboardType(.URL)
                    Button("Update Subscription") { Task { await store.updateSubscription() } }
                    Button("Import Offline Text / Base64") { showImport = true }
                } header: { Text("Subscription") } footer: {
                    Text("Downloads require an already connected proxy. For the first connection, import offline text or connect a manual proxy. Updating replaces nodes atomically; failures keep the previous list. Supported entries: SS, VMess, VLESS and Trojan. Unsupported options are rejected.")
                }
                Section("Nodes") {
                    ForEach(store.settings.nodes) { node in
                        Button {
                            store.settings.selectedNodeID = node.id
                        } label: {
                            HStack {
                                VStack(alignment: .leading) {
                                    Text(node.name).foregroundStyle(.primary)
                                    Text(node.type.uppercased()).font(.caption).foregroundStyle(.secondary)
                                }
                                Spacer()
                                if store.settings.selectedNodeID == node.id {
                                    Image(systemName: "checkmark.circle.fill")
                                }
                            }
                        }
                    }.onDelete(perform: store.removeNodes)
                }
            }
            if store.mode != "off" {
                Section {
                    Toggle("Allow Proxy Server DNS Bootstrap", isOn: $store.settings.allowBootstrapDNS)
                } footer: {
                    Text("Allows system DNS only to resolve the proxy server's hostname before the tunnel exists. Business DNS remains proxied. Leave off and use a server IP address to avoid this bootstrap lookup.")
                }
            }
            Section {
                Button(store.mode == "off" ? "Apply Off" : "Connect") { store.apply() }
                Button("Test HTTPS Connection to Apple") { Task { await store.testConnection() } }
            }.disabled(store.busy)
            Section("Scope and Privacy") {
                Text("Credentials, subscription URLs and node details are saved in this device's Keychain and excluded from sync. Switching cancels active app connections; some provider clients may need to be reopened.")
                Text("iCloud, CloudKit and system-managed sign-in cannot be forced through an app proxy. Controllable unsupported services are disabled while strict routing is enabled. Shared APNs delivery is controlled by iOS.")
                Text("Apple weather, maps and network-assisted location are paused in strict mode. Apple speech requires supported on-device recognition; online speech can use a configured external provider through the proxy.")
                Text("Connection testing sends a request to apple.com using the selected proxy.")
            }.font(.footnote).foregroundStyle(.secondary)
        }
        .navigationTitle("Network Proxy")
        .sheet(isPresented: $showImport) {
            NavigationStack {
                Form {
                    TextEditor(text: $importText).frame(minHeight: 240)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                    Text("Paste a subscription body or newline-separated proxy links. Imported credentials remain in Keychain.")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                .navigationTitle("Import Proxy Nodes")
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { importText = ""; showImport = false }
                    }
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Import") { store.importText(importText); importText = ""; showImport = false }
                            .disabled(importText.isEmpty)
                    }
                }
            }
        }
    }
}
