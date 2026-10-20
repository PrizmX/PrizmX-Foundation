import Foundation

/// Converts a share-link subscription body (one link per line: `ss://`,
/// `ssr://`, `vmess://`, `vless://`, `trojan://`, `anytls://`, `socks5://`,
/// …) into Clash YAML for the regular importer. Panels such as V2Board send
/// this format, usually base64-wrapped, to clients they do not recognize as
/// Clash.
///
/// Links for protocols PrizmX cannot dial (Hysteria, TUIC, WireGuard) become
/// entries of that type, so the importer reports them instead of dropping
/// them silently.
public enum ProxyURIList {
    /// Select group that the catch-all rule targets.
    public static let selectGroupName = "Proxy"
    /// URL-test group listed first in `selectGroupName`.
    public static let autoGroupName = "Auto"

    /// Clash YAML for `text`, or nil when `text` is not a share-link list.
    public static func clashYAML(from text: String) -> String? {
        let lines = text
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        // Every line must be a link: anything else (YAML, JSON, an HTML
        // error page) is not this format.
        guard !lines.isEmpty, lines.allSatisfy({ $0.contains("://") }) else { return nil }
        var proxies: [Entry] = []
        var names = Set([selectGroupName, autoGroupName, "DIRECT", "REJECT"])
        for line in lines {
            guard var entry = parseLink(line) else { continue }
            entry.name = uniqueName(entry.name, in: &names)
            proxies.append(entry)
        }
        guard !proxies.isEmpty else { return nil }
        return render(proxies)
    }

    /// Base64 (standard or URL-safe, padding optional, line breaks allowed)
    /// to UTF-8 text.
    public static func decodeBase64(_ text: String) -> String? {
        var compact = String(text.unicodeScalars.filter { !CharacterSet.whitespacesAndNewlines.contains($0) })
        compact = compact
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        guard !compact.isEmpty else { return nil }
        let remainder = compact.count % 4
        if remainder == 1 { return nil }
        if remainder > 0 {
            compact += String(repeating: "=", count: 4 - remainder)
        }
        guard let data = Data(base64Encoded: compact) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    // MARK: - Model

    /// One Clash proxy mapping. Keys keep their order in the YAML.
    struct Entry {
        var name: String
        var fields: [(String, Value)]
    }

    indirect enum Value {
        case string(String)
        case list([String])
        case map([(String, Value)])
    }

    // MARK: - Links

    static func parseLink(_ line: String) -> Entry? {
        guard let schemeEnd = line.range(of: "://") else { return nil }
        let scheme = line[..<schemeEnd.lowerBound].lowercased()
        let rest = String(line[schemeEnd.upperBound...])
        switch scheme {
        case "ss": return parseShadowsocks(rest)
        case "ssr": return parseShadowsocksR(rest)
        case "vmess": return parseVMess(rest)
        case "vless": return parseVLESS(rest)
        case "trojan": return parseTrojan(rest)
        case "anytls": return parseAnyTLS(rest)
        case "socks", "socks5": return parseSOCKS5(rest)
        case "hysteria2", "hy2": return parseUnsupported(rest, type: "hysteria2")
        case "hysteria": return parseUnsupported(rest, type: "hysteria")
        case "tuic": return parseUnsupported(rest, type: "tuic")
        case "wireguard", "wg": return parseUnsupported(rest, type: "wireguard")
        default: return nil
        }
    }

    /// SIP002 `ss://base64(method:password)@host:port/?plugin=…#name`, the
    /// plain `method:password@…` form (SS 2022), and the legacy
    /// `ss://base64(method:password@host:port)#name`.
    private static func parseShadowsocks(_ rest: String) -> Entry? {
        let (body, fragment) = splitFragment(rest)
        let (main, query) = splitQuery(body)
        var userInfo: String
        var hostPort: String
        if let at = main.lastIndex(of: "@") {
            let rawUser = String(main[..<at])
            userInfo = decodeBase64(rawUser).flatMap { $0.contains(":") ? $0 : nil }
                ?? rawUser.removingPercentEncoding
                ?? rawUser
            hostPort = String(main[main.index(after: at)...])
        } else {
            guard let decoded = decodeBase64(main), let at = decoded.lastIndex(of: "@") else { return nil }
            userInfo = String(decoded[..<at])
            hostPort = String(decoded[decoded.index(after: at)...])
        }
        if hostPort.hasSuffix("/") { hostPort.removeLast() }
        guard let colon = userInfo.firstIndex(of: ":"),
              let (host, port) = splitHostPort(hostPort)
        else { return nil }
        let method = String(userInfo[..<colon])
        let password = String(userInfo[userInfo.index(after: colon)...])
        var fields: [(String, Value)] = [
            ("type", .string("ss")),
            ("server", .string(host)),
            ("port", .string(port)),
            ("cipher", .string(method)),
            ("password", .string(password)),
        ]
        if let plugin = query["plugin"], !plugin.isEmpty {
            fields += shadowsocksPlugin(plugin, server: host)
        }
        return Entry(name: fragment ?? "\(host):\(port)", fields: fields)
    }

    /// `obfs-local;obfs=http;obfs-host=…` or `v2ray-plugin;tls;host=…;path=…`.
    private static func shadowsocksPlugin(_ raw: String, server: String) -> [(String, Value)] {
        let parts = raw.split(separator: ";", maxSplits: 1).map(String.init)
        // `plugin=;` splits to nothing.
        guard let first = parts.first else { return [] }
        let name = first.lowercased()
        let options = ConfigMapping.sip003Options(parts.count > 1 ? parts[1] : nil)
        switch name {
        case "obfs-local", "simple-obfs", "obfs":
            var opts: [(String, Value)] = [("mode", .string(options["obfs"] ?? options["mode"] ?? "http"))]
            if let host = options["obfs-host"] ?? options["host"] { opts.append(("host", .string(host))) }
            if let path = options["obfs-uri"] ?? options["path"] { opts.append(("path", .string(path))) }
            return [("plugin", .string("obfs")), ("plugin-opts", .map(opts))]
        case "v2ray-plugin":
            var opts: [(String, Value)] = [("mode", .string(options["mode"] ?? "websocket"))]
            if let host = options["host"] { opts.append(("host", .string(host))) }
            if let path = options["path"] { opts.append(("path", .string(path))) }
            if options["tls"] != nil { opts.append(("tls", .string("true"))) }
            if let mux = options["mux"] { opts.append(("mux", .string(mux))) }
            return [("plugin", .string("v2ray-plugin")), ("plugin-opts", .map(opts))]
        default:
            // Passed through so the importer reports the unsupported plugin.
            return [("plugin", .string(name))]
        }
    }

    /// `ssr://base64(host:port:protocol:method:obfs:base64(password)/?obfsparam=…&protoparam=…&remarks=…)`.
    private static func parseShadowsocksR(_ rest: String) -> Entry? {
        guard let decoded = decodeBase64(rest) else { return nil }
        let pieces = decoded.components(separatedBy: "/?")
        let parts = pieces[0].split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count >= 6, let password = decodeBase64(parts[parts.count - 1]) else { return nil }
        let host = parts[0..<(parts.count - 5)].joined(separator: ":")
        let port = parts[parts.count - 5]
        var params: [String: String] = [:]
        if pieces.count > 1 {
            for pair in pieces[1].split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
                guard kv.count == 2 else { continue }
                params[kv[0]] = decodeBase64(kv[1]) ?? ""
            }
        }
        var fields: [(String, Value)] = [
            ("type", .string("ssr")),
            ("server", .string(host)),
            ("port", .string(port)),
            ("cipher", .string(parts[parts.count - 3])),
            ("password", .string(password)),
            ("protocol", .string(parts[parts.count - 4])),
            ("obfs", .string(parts[parts.count - 2])),
        ]
        if let value = params["protoparam"], !value.isEmpty { fields.append(("protocol-param", .string(value))) }
        if let value = params["obfsparam"], !value.isEmpty { fields.append(("obfs-param", .string(value))) }
        let remarks = params["remarks"].flatMap { $0.isEmpty ? nil : $0 }
        return Entry(name: remarks ?? "\(host):\(port)", fields: fields)
    }

    /// v2rayN `vmess://base64(json)`.
    private static func parseVMess(_ rest: String) -> Entry? {
        let (body, _) = splitFragment(rest)
        guard let json = decodeBase64(body),
              let data = json.data(using: .utf8),
              let object = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        func value(_ key: String) -> String? {
            switch object[key] {
            case let string as String: return string.isEmpty ? nil : string
            case let number as NSNumber: return number.stringValue
            default: return nil
            }
        }
        guard let host = value("add"), let port = value("port"), let uuid = value("id") else { return nil }
        let tls = value("tls")?.lowercased() == "tls"
        var fields: [(String, Value)] = [
            ("type", .string("vmess")),
            ("server", .string(host)),
            ("port", .string(port)),
            ("uuid", .string(uuid)),
            ("alterId", .string(value("aid") ?? "0")),
            ("cipher", .string(value("scy") ?? "auto")),
        ]
        if tls {
            fields.append(("tls", .string("true")))
            if let sni = value("sni") ?? value("host") { fields.append(("servername", .string(sni))) }
            if let alpn = value("alpn") { fields.append(("alpn", .list(splitList(alpn)))) }
        }
        // TCP with an HTTP header (`type: http`) is a different transport;
        // pass it through so the importer reports it.
        let headerType = value("type")?.lowercased()
        let network = (value("net") ?? "tcp") == "tcp" && headerType == "http" ? "http" : value("net")
        fields += transport(
            network: network,
            host: value("host"),
            path: value("path"),
            serviceName: value("path")
        )
        return Entry(name: value("ps") ?? "\(host):\(port)", fields: fields)
    }

    /// `vless://uuid@host:port?security=tls|reality&sni=…&type=ws&…#name`.
    private static func parseVLESS(_ rest: String) -> Entry? {
        guard let link = Link(rest), let uuid = link.user else { return nil }
        let query = link.query
        let security = query["security"]?.lowercased() ?? "none"
        var fields: [(String, Value)] = [
            ("type", .string("vless")),
            ("server", .string(link.host)),
            ("port", .string(link.port)),
            ("uuid", .string(uuid)),
        ]
        if security == "tls" || security == "reality" || security == "xtls" {
            fields.append(("tls", .string("true")))
        }
        if let sni = query["sni"] ?? query["peer"] { fields.append(("servername", .string(sni))) }
        if let flow = query["flow"], !flow.isEmpty { fields.append(("flow", .string(flow))) }
        if isTrue(query["allowinsecure"] ?? query["insecure"]) {
            fields.append(("skip-cert-verify", .string("true")))
        }
        if let alpn = query["alpn"] { fields.append(("alpn", .list(splitList(alpn)))) }
        if let fingerprint = query["fp"] { fields.append(("client-fingerprint", .string(fingerprint))) }
        if security == "reality", let publicKey = query["pbk"] {
            var reality: [(String, Value)] = [("public-key", .string(publicKey))]
            if let shortID = query["sid"] { reality.append(("short-id", .string(shortID))) }
            if let spiderX = query["spx"] { reality.append(("spider-x", .string(spiderX))) }
            fields.append(("reality-opts", .map(reality)))
        }
        fields += transport(
            network: query["type"],
            host: query["host"],
            path: query["path"],
            serviceName: query["servicename"]
        )
        return Entry(name: link.fragment ?? "\(link.host):\(link.port)", fields: fields)
    }

    /// `trojan://password@host:port?sni=…&type=ws&…#name`.
    private static func parseTrojan(_ rest: String) -> Entry? {
        guard let link = Link(rest), let password = link.user else { return nil }
        let query = link.query
        var fields: [(String, Value)] = [
            ("type", .string("trojan")),
            ("server", .string(link.host)),
            ("port", .string(link.port)),
            ("password", .string(password)),
        ]
        if let sni = query["sni"] ?? query["peer"] { fields.append(("sni", .string(sni))) }
        if isTrue(query["allowinsecure"] ?? query["insecure"]) {
            fields.append(("skip-cert-verify", .string("true")))
        }
        if let alpn = query["alpn"] { fields.append(("alpn", .list(splitList(alpn)))) }
        fields += transport(
            network: query["type"],
            host: query["host"],
            path: query["path"],
            serviceName: query["servicename"]
        )
        return Entry(name: link.fragment ?? "\(link.host):\(link.port)", fields: fields)
    }

    /// `anytls://password@host:port?sni=…&insecure=1#name`.
    private static func parseAnyTLS(_ rest: String) -> Entry? {
        guard let link = Link(rest), let password = link.user else { return nil }
        var fields: [(String, Value)] = [
            ("type", .string("anytls")),
            ("server", .string(link.host)),
            ("port", .string(link.port)),
            ("password", .string(password)),
        ]
        if let sni = link.query["sni"] ?? link.query["peer"] { fields.append(("sni", .string(sni))) }
        if isTrue(link.query["allowinsecure"] ?? link.query["insecure"]) {
            fields.append(("skip-cert-verify", .string("true")))
        }
        return Entry(name: link.fragment ?? "\(link.host):\(link.port)", fields: fields)
    }

    /// `socks5://user:pass@host:port#name`; the user info may be base64.
    private static func parseSOCKS5(_ rest: String) -> Entry? {
        guard let link = Link(rest) else { return nil }
        var fields: [(String, Value)] = [
            ("type", .string("socks5")),
            ("server", .string(link.host)),
            ("port", .string(link.port)),
        ]
        if var user = link.user {
            var password = link.password
            if password == nil, let decoded = decodeBase64(user), let colon = decoded.firstIndex(of: ":") {
                password = String(decoded[decoded.index(after: colon)...])
                user = String(decoded[..<colon])
            }
            fields.append(("username", .string(user)))
            if let password { fields.append(("password", .string(password))) }
        }
        return Entry(name: link.fragment ?? "\(link.host):\(link.port)", fields: fields)
    }

    private static func parseUnsupported(_ rest: String, type: String) -> Entry? {
        guard let link = Link(rest) else { return nil }
        return Entry(
            name: link.fragment ?? "\(link.host):\(link.port)",
            fields: [
                ("type", .string(type)),
                ("server", .string(link.host)),
                ("port", .string(link.port)),
            ]
        )
    }

    /// Clash `network` plus its options for the share-link `type` / `net`.
    private static func transport(
        network: String?,
        host: String?,
        path: String?,
        serviceName: String?
    ) -> [(String, Value)] {
        switch network?.lowercased() ?? "tcp" {
        case "", "tcp", "raw", "none":
            return []
        case "ws":
            var opts: [(String, Value)] = [("path", .string(path ?? "/"))]
            if let host { opts.append(("headers", .map([("Host", .string(host))]))) }
            return [("network", .string("ws")), ("ws-opts", .map(opts))]
        case "httpupgrade":
            var opts: [(String, Value)] = [
                ("path", .string(path ?? "/")),
                ("v2ray-http-upgrade", .string("true")),
            ]
            if let host { opts.append(("headers", .map([("Host", .string(host))]))) }
            return [("network", .string("ws")), ("ws-opts", .map(opts))]
        case "grpc":
            return [
                ("network", .string("grpc")),
                ("grpc-opts", .map([("grpc-service-name", .string(serviceName ?? ""))])),
            ]
        case let other:
            // h2, kcp, quic, xhttp…: passed through so the importer reports them.
            return [("network", .string(other))]
        }
    }

    // MARK: - Link parsing helpers

    /// `user[:password]@host:port[/][?query][#fragment]`, decoded.
    private struct Link {
        var user: String?
        var password: String?
        var host: String
        var port: String
        var query: [String: String]
        var fragment: String?

        init?(_ rest: String) {
            let (body, fragment) = ProxyURIList.splitFragment(rest)
            let (main, query) = ProxyURIList.splitQuery(body)
            var hostPort = main
            if let at = main.lastIndex(of: "@") {
                let info = String(main[..<at])
                if let colon = info.firstIndex(of: ":") {
                    user = String(info[..<colon]).removingPercentEncoding
                    password = String(info[info.index(after: colon)...]).removingPercentEncoding
                } else {
                    user = info.removingPercentEncoding
                }
                hostPort = String(main[main.index(after: at)...])
            }
            if hostPort.hasSuffix("/") { hostPort.removeLast() }
            guard let (host, port) = ProxyURIList.splitHostPort(hostPort) else { return nil }
            self.host = host
            self.port = port
            self.query = query
            self.fragment = fragment
        }
    }

    /// Splits `#name` off; the name is percent-decoded and trimmed.
    static func splitFragment(_ text: String) -> (String, String?) {
        guard let hash = text.firstIndex(of: "#") else { return (text, nil) }
        let raw = String(text[text.index(after: hash)...])
        let name = (raw.removingPercentEncoding ?? raw).trimmingCharacters(in: .whitespaces)
        return (String(text[..<hash]), name.isEmpty ? nil : name)
    }

    /// Splits `?a=b&c=d` off; keys are lowercased, values percent-decoded.
    static func splitQuery(_ text: String) -> (String, [String: String]) {
        guard let mark = text.firstIndex(of: "?") else { return (text, [:]) }
        var query: [String: String] = [:]
        for pair in text[text.index(after: mark)...].split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1).map(String.init)
            guard let key = kv.first, !key.isEmpty else { continue }
            let raw = kv.count == 2 ? kv[1] : ""
            query[key.lowercased()] = raw.replacingOccurrences(of: "+", with: " ").removingPercentEncoding ?? raw
        }
        return (String(text[..<mark]), query)
    }

    /// `host:port` or `[v6]:port`; the port must be 1…65535.
    static func splitHostPort(_ text: String) -> (String, String)? {
        let host: String
        let port: String
        if text.hasPrefix("["), let close = text.firstIndex(of: "]") {
            host = String(text[text.index(after: text.startIndex)..<close])
            let after = text[text.index(after: close)...]
            guard after.hasPrefix(":") else { return nil }
            port = String(after.dropFirst())
        } else {
            guard let colon = text.lastIndex(of: ":") else { return nil }
            host = String(text[..<colon])
            port = String(text[text.index(after: colon)...])
        }
        guard !host.isEmpty, let number = Int(port), (1...65_535).contains(number) else { return nil }
        return (host, String(number))
    }

    private static func splitList(_ raw: String) -> [String] {
        raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    private static func isTrue(_ raw: String?) -> Bool {
        guard let raw = raw?.lowercased() else { return false }
        return raw == "1" || raw == "true"
    }

    private static func uniqueName(_ name: String, in names: inout Set<String>) -> String {
        var candidate = name
        var suffix = 2
        while names.contains(candidate) {
            candidate = "\(name) \(suffix)"
            suffix += 1
        }
        names.insert(candidate)
        return candidate
    }

    // MARK: - YAML

    /// Every scalar is double-quoted, so names and passwords never need
    /// YAML-specific care.
    private static func render(_ proxies: [Entry]) -> String {
        var lines = ["# Converted by PrizmX from a share-link subscription.", "proxies:"]
        for proxy in proxies {
            lines.append("  - name: \(quoted(proxy.name))")
            appendFields(proxy.fields, indent: 4, into: &lines)
        }
        let members = proxies.map(\.name)
        lines.append("proxy-groups:")
        lines.append("  - name: \(quoted(selectGroupName))")
        lines.append("    type: \"select\"")
        lines.append("    proxies:")
        for member in [autoGroupName] + members {
            lines.append("      - \(quoted(member))")
        }
        lines.append("  - name: \(quoted(autoGroupName))")
        lines.append("    type: \"url-test\"")
        lines.append("    url: \"http://www.gstatic.com/generate_204\"")
        lines.append("    interval: \"300\"")
        lines.append("    proxies:")
        for member in members {
            lines.append("      - \(quoted(member))")
        }
        // Share links carry no rules: keep local networks direct and send
        // everything else through the select group.
        lines.append("rules:")
        for cidr in ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"] {
            lines.append("  - \(quoted("IP-CIDR,\(cidr),DIRECT,no-resolve"))")
        }
        lines.append("  - \(quoted("MATCH,\(selectGroupName)"))")
        return lines.joined(separator: "\n") + "\n"
    }

    private static func appendFields(_ fields: [(String, Value)], indent: Int, into lines: inout [String]) {
        let pad = String(repeating: " ", count: indent)
        for (key, value) in fields {
            switch value {
            case .string(let text):
                lines.append("\(pad)\(key): \(quoted(text))")
            case .list(let items):
                lines.append("\(pad)\(key):")
                for item in items {
                    lines.append("\(pad)  - \(quoted(item))")
                }
            case .map(let nested):
                lines.append("\(pad)\(key):")
                appendFields(nested, indent: indent + 2, into: &lines)
            }
        }
    }

    /// YAML double-quoted scalar (JSON escapes are valid YAML escapes).
    static func quoted(_ text: String) -> String {
        var out = "\""
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 || scalar.value == 0x7F {
                    out += String(format: "\\u%04X", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }
}
