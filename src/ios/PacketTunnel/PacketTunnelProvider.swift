import NetworkExtension
import Foundation

/// Minimal PacketTunnel provider for the built-in-VPN verification build.
///
/// On start it receives the Xray JSON config (built by the app, global
/// routing) through the tunnel protocol configuration, starts the Go TUN
/// bridge (which starts Xray inside this extension process and terminates
/// IP flows in a gVisor netstack forwarded to the core's SOCKS inbound),
/// and pumps raw packets between NEPacketTunnelFlow and the bridge.
final class PacketTunnelProvider: NEPacketTunnelProvider {

    private let stateLock = NSLock()
    private var _running = false
    private var running: Bool {
        get { stateLock.lock(); defer { stateLock.unlock() }; return _running }
        set { stateLock.lock(); _running = newValue; stateLock.unlock() }
    }
    private var drainThread: Thread?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        guard let proto = protocolConfiguration as? NETunnelProviderProtocol,
              let json = proto.providerConfiguration?["xrayConfig"] as? String,
              !json.isEmpty else {
            completionHandler(NSError(domain: "MinisVPN", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "缺少节点配置"]))
            return
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["10.0.0.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]
        settings.ipv4Settings = ipv4
        settings.dnsSettings = NEDNSSettings(servers: ["223.5.5.5", "8.8.8.8"])
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error {
                completionHandler(error)
                return
            }
            guard let self else {
                completionHandler(NSError(domain: "MinisVPN", code: 3,
                    userInfo: [NSLocalizedDescriptionKey: "扩展已释放"]))
                return
            }
            let errStr: String = json.withCString { ptr in
                guard let out = MinisTunStart(UnsafeMutablePointer(mutating: ptr)) else {
                    return "bridge start failed"
                }
                defer { MinisRcloneFreeString(out) }
                return String(cString: out)
            }
            if !errStr.isEmpty {
                completionHandler(NSError(domain: "MinisVPN", code: 2,
                    userInfo: [NSLocalizedDescriptionKey: errStr]))
                return
            }
            self.running = true
            self.startInboundPump()
            self.startOutboundPump()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        running = false
        MinisTunStop()
        completionHandler()
    }

    // MARK: - Packet pumps

    private func startInboundPump() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.running else { return }
            for (index, data) in packets.enumerated() {
                let family = protocols[index].int32Value
                data.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress else { return }
                    MinisTunWritePacket(
                        UnsafeMutablePointer(mutating: base.assumingMemoryBound(to: UInt8.self)),
                        CInt(data.count),
                        CInt(family))
                }
            }
            if self.running {
                self.startInboundPump()
            }
        }
    }

    private func startOutboundPump() {
        let thread = Thread { [weak self] in
            var buffer = [UInt8](repeating: 0, count: 65536)
            while let self, self.running {
                let n = buffer.withUnsafeMutableBufferPointer { bp -> Int in
                    guard let base = bp.baseAddress else { return 0 }
                    return Int(MinisTunReadPacket(base, CInt(bp.count)))
                }
                if n > 1 {
                    let family = buffer[0]
                    let payload = Data(buffer[1..<n])
                    self.packetFlow.writePackets([payload],
                                                 protocols: [NSNumber(value: Int32(family))])
                } else {
                    Thread.sleep(forTimeInterval: 0.003)
                }
            }
        }
        thread.name = "MinisTunDrain"
        thread.qualityOfService = .userInitiated
        thread.start()
        drainThread = thread
    }
}
