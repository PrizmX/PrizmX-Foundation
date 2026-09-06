import Foundation
import Testing
@testable import PrizmXRules

@Test func geositeDatParsesExactSuffixAndKeyword() throws {
    let data = GeositeDatWriter.encode([
        (
            tag: "cn",
            domains: [
                (type: 3, value: "www.baidu.com"),
                (type: 2, value: "qq.com"),
                (type: 0, value: "weixin"),
            ]
        ),
        (
            tag: "google",
            domains: [(type: 2, value: "google.com")]
        ),
    ])
    let matcher = try GeositeDatParser.parse(data: data)
    #expect(matcher.match(domain: "www.baidu.com", group: "cn"))
    #expect(matcher.match(domain: "x.qq.com", group: "cn"))
    #expect(matcher.match(domain: "weixin.qq.com", group: "cn"))
    #expect(!matcher.match(domain: "google.com", group: "cn"))
    #expect(matcher.match(domain: "www.google.com", group: "google"))
}

@Test func geositeDatSkipsRegexAndHonorsIncludeTags() throws {
    let data = GeositeDatWriter.encode([
        (tag: "cn", domains: [(type: 2, value: "baidu.com"), (type: 1, value: ".*\\.cn")]),
        (tag: "ads", domains: [(type: 2, value: "doubleclick.net")]),
    ])
    let matcher = try GeositeDatParser.parse(data: data, includeTags: ["CN"])
    #expect(matcher.match(domain: "tieba.baidu.com", group: "cn"))
    #expect(!matcher.match(domain: "foo.cn", group: "cn"))
    #expect(!matcher.match(domain: "doubleclick.net", group: "ads"))
}

enum GeositeDatWriter {
    static func encode(_ sites: [(tag: String, domains: [(type: UInt64, value: String)])]) -> Data {
        var list = Data()
        for site in sites {
            var message = Data()
            appendString(&message, field: 1, site.tag)
            for domain in site.domains {
                var body = Data()
                appendVarintField(&body, field: 1, domain.type)
                appendString(&body, field: 2, domain.value)
                appendBytes(&message, field: 2, body)
            }
            appendBytes(&list, field: 1, message)
        }
        return list
    }

    private static func appendString(_ data: inout Data, field: Int, _ value: String) {
        appendBytes(&data, field: field, Data(value.utf8))
    }

    private static func appendBytes(_ data: inout Data, field: Int, _ value: Data) {
        appendVarint(&data, UInt64((field << 3) | 2))
        appendVarint(&data, UInt64(value.count))
        data.append(value)
    }

    private static func appendVarintField(_ data: inout Data, field: Int, _ value: UInt64) {
        appendVarint(&data, UInt64(field << 3))
        appendVarint(&data, value)
    }

    private static func appendVarint(_ data: inout Data, _ value: UInt64) {
        var current = value
        while current > 127 {
            data.append(UInt8(current & 0x7F) | 0x80)
            current >>= 7
        }
        data.append(UInt8(current))
    }
}
