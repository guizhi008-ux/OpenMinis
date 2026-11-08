# iPhone 应用内网络代理

本分支增加 OpenMinis 自身的代理配置，不能修改已安装的 App Store 版本。
需要从修改后的源码在 Mac 上编译、签名并安装。

## 使用

1. 打开设置 → Network Proxy。
2. 手动模式填写 HTTP CONNECT / HTTPS CONNECT / SOCKS5 的地址、端口和
   可选账号密码；或离线粘贴小火箭节点列表，选择节点后连接。
3. 更新 HTTPS 订阅需要先有一个可用代理。没有时使用离线导入；不会默默
   直接下载带秘密的订阅 URL。
4. 节点服务器使用域名时，只有明确开启 bootstrap DNS 才允许使用系统
   DNS 解析代理服务器自身地址。业务域名经代理解析。
5. 连接测试检查实际 HTTPS 出口。更换代理会取消旧请求并清空正在浏览的
   页面，需要重新加载；模型长任务可能中断。

订阅首期识别常见纯文本或整体 Base64 列表中的 SS、VMess、VLESS、Trojan。
VLESS 与 Trojan 支持 security=reality（pbk 公钥必填、sid 短 ID 可选、
fp 指纹缺省 chrome；Reality 仅限 TCP 传输，含 Vision 流）。插件、SSR、
完整 Clash/sing-box 配置及未支持的传输参数会明确拒绝，不能保证所有
标注为“小火箭订阅”的服务都兼容。

## 严格代理范围

受管流量包括模型、HTTP/HTTPS/WebSocket、内置浏览器与 WebApp、图片和
受管媒体下载、MCP、小系统 IPv4/IPv6 TCP/UDP/DNS、rclone 远程连接。
小系统透明转发适用于不读取 HTTP_PROXY 的程序；不会修改其他 App 的路由。

入口停止、节点失效或能力不支持时受管流量失败，不自动直连。
HTTP 上游不能传 UDP 时明确失败；SOCKS5 节点支持 UDP ASSOCIATE 时可转发。
小系统 DNS 经所选代理以 TCP 查询公共解析器 1.1.1.1:53；不使用本地 LAN
DNS，也不保持公司私有 DNS 的语义。

回环内部服务、到代理服务器的底层连接和明确同意的 bootstrap DNS 是必要
例外。原始 IP/ICMP 等未适配能力不作为已支持功能。

## iOS 系统服务限制

普通应用不能把 iCloud/CloudKit、APNs、iCloud Keychain 或系统托管登录页
全部强制放进自己的代理。严格模式阻止可控制的同步、外部文件提供商挂载、
相关备份和系统登录入口；保留原来的设置与凭据。
已交给系统的任务、已有可同步 Keychain 项及系统共享连接无法保证撤回。
Apple 天气、地图搜索/路线/地理编码及网络辅助定位也无法使用应用代理，
严格模式会停用这些原生入口。系统语音仅允许受支持的设备端识别，不再
回退到 Apple 云识别；需要在线语音时可使用已配置的受管外部服务。
系统分享面板、文件选择器及打开其他 App 后的行为由 iOS/目标 App 控制，
不属于应用内部代理的覆盖承诺。

## 构建和验证

见根目录 BUILDING.md。核心 sing-box v1.14.4 与 rclone/Tailscale 使用
同一 Go runtime。iSH 补丁绑定项目固定子模块版本，构建时应用。
不要另行链接一个包含 Go runtime 的代理 XCFramework。

当前开发环境为 Linux。Go 核心、网络模块和独立 C 适配器测试可以运行；
Swift/WebKit XCTest、完整 Xcode 构建签名和 iPhone 真机出口验证需要 Mac。
这些检查通过之前，本分支不能描述为已经在 iPhone 上验证可用。
