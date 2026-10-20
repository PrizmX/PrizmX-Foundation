import Foundation
import Testing
@testable import PrizmXConfig
import PrizmXNodes

/// Constructs the subset parser could not read, which popular mihomo
/// templates use: anchors, merge keys, block scalars, multi-line flow.
@Suite struct YAMLLibyamlTests {
    @Test func anchorsAndMergeKeysBuildGroups() throws {
        let yaml = """
        p: &p {type: select, url: "http://www.gstatic.com/generate_204"}
        auto: &auto
          type: url-test
          interval: 300
        proxies:
          - name: a
            type: ss
            server: 1.1.1.1
            port: 8388
            cipher: aes-256-gcm
            password: x
        proxy-groups:
          - {name: Proxy, <<: *p, proxies: [Auto, a]}
          - name: Auto
            <<: *auto
            proxies: [a]
          - name: Override
            <<: [*auto, *p]
            type: fallback
            proxies: [a]
        rules:
          - MATCH,Proxy
        """
        let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
        let groups = result.nodeManager.groupsByName
        #expect(groups["Proxy"]?.mode == .select)
        #expect(groups["Proxy"]?.nodeIDs == ["Auto", "a"])
        #expect(groups["Auto"]?.mode == .urlTest)
        // Explicit keys beat merged ones; the earlier merged mapping beats later ones.
        #expect(groups["Override"]?.mode == .fallback)
        #expect(result.unroutableCatchAllTarget == nil)
    }

    @Test func blockScalarsAndMultiLineFlowParse() throws {
        let yaml = """
        script:
          code: |
            def main(ctx, metadata):
              return "DIRECT"
        proxies:
          - {
              name: b, type: trojan,
              server: example.com, port: 443,
              password: "p#1", sni: example.com
            }
        rules: [
          "DOMAIN-SUFFIX,example.com,b",
          "MATCH,DIRECT"
        ]
        """
        let root = try YAMLParser.parse(yaml)
        #expect(root.mapping?["script"]?.string(for: "code")?.contains("return \"DIRECT\"") == true)
        let result = try ConfigAdapter.parseWithWarnings(rawString: yaml)
        #expect(result.nodeManager.nodesByID["b"] != nil)
        #expect(result.router.rules.count == 2)
    }

    @Test func plainNullIsEmptyButQuotedNullIsText() throws {
        let root = try YAMLParser.parse("a: ~\nb: null\nc: \"null\"\nd: '~'\n")
        #expect(root.string(for: "a") == "")
        #expect(root.string(for: "b") == "")
        #expect(root.string(for: "c") == "null")
        #expect(root.string(for: "d") == "~")
    }

    @Test func emojiEscapesAndHashesSurvive() throws {
        let root = try YAMLParser.parse("name: \"\\U0001F1ED\\U0001F1F0 HK\"\npassword: abc#123\n")
        #expect(root.string(for: "name") == "🇭🇰 HK")
        #expect(root.string(for: "password") == "abc#123")
    }

    /// libyaml rejects tab indentation; files earlier builds imported keep
    /// importing through the lenient parser.
    @Test func tabIndentedFilesFallBackToTheLenientParser() throws {
        let yaml = "proxies: []\nrules:\n\t- MATCH,DIRECT\n"
        let root = try YAMLParser.parse(yaml)
        #expect(root.mapping?["rules"]?.sequence?.first?.string == "MATCH,DIRECT")
    }

    @Test func nestedAliasesCannotExplode() {
        var lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
        for level in 1...9 {
            let refs = Array(repeating: "*a\(level - 1)", count: 10).joined(separator: ", ")
            lines.append("a\(level): &a\(level) [\(refs)]")
        }
        #expect(throws: ConfigError.self) {
            _ = try YAMLParser.parse(lines.joined(separator: "\n"))
        }
    }

    @Test func syntaxErrorsDoNotQuoteTheSourceLine() {
        let yaml = "proxies:\n  - name: a\n    password: \"secret-token\n  - broken: [\n"
        do {
            _ = try YAMLParser.parse(yaml)
            Issue.record("expected a syntax error")
        } catch {
            #expect(!"\(error)".contains("secret-token"))
        }
    }
}
