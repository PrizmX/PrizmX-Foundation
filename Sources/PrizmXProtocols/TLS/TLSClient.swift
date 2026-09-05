import Foundation
import Network
import Security

/// Shared `NWParameters.tls` builder for Trojan / AnyTLS / VLESS-style outbounds.
enum TLSClient {
    /// TLS options with SNI. AnyTLS pins 1.3; Trojan keeps the platform default
    /// range (1.2…1.3) so it can talk to older trojan-gfw servers.
    static func options(
        serverName: String?,
        minimum: tls_protocol_version_t? = nil,
        maximum: tls_protocol_version_t? = nil,
        requirePeerAuthentication: Bool = true,
        skipVerification: Bool = false
    ) -> NWProtocolTLS.Options {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        if let minimum {
            sec_protocol_options_set_min_tls_protocol_version(sec, minimum)
        }
        if let maximum {
            sec_protocol_options_set_max_tls_protocol_version(sec, maximum)
        }
        if skipVerification {
            // Clash `skip-cert-verify`: accept self-signed / mismatched edge certs.
            sec_protocol_options_set_peer_authentication_required(sec, false)
            sec_protocol_options_set_verify_block(sec, { _, _, completion in
                completion(true)
            }, .global(qos: .userInitiated))
        } else {
            sec_protocol_options_set_peer_authentication_required(sec, requirePeerAuthentication)
        }
        if let serverName, !serverName.isEmpty {
            serverName.withCString { pointer in
                sec_protocol_options_set_tls_server_name(sec, pointer)
            }
        }
        return tls
    }

    static func parameters(
        serverName: String?,
        minimum: tls_protocol_version_t? = nil,
        maximum: tls_protocol_version_t? = nil,
        skipVerification: Bool = false
    ) -> NWParameters {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        tcp.keepaliveIdle = 20
        tcp.keepaliveInterval = 5
        tcp.keepaliveCount = 4
        tcp.connectionTimeout = 8
        let parameters = NWParameters(
            tls: options(
                serverName: serverName,
                minimum: minimum,
                maximum: maximum,
                skipVerification: skipVerification
            ),
            tcp: tcp
        )
        parameters.preferNoProxies = true
        return parameters
    }

    static func resolvedServerName(explicit: String?, server: Endpoint) -> String? {
        if let explicit, !explicit.isEmpty { return explicit }
        if case .domain(let domain) = server.host { return domain }
        return nil
    }
}
