import Foundation

/// Minimal YAML 1.1 subset used by Clash configs: block mappings/sequences,
/// quoted scalars, and one-line flow maps/lists. Not a full YAML 1.2 implementation.
enum YAMLNode: Equatable, Sendable {
    case scalar(String)
    case mapping([String: YAMLNode])
    case sequence([YAMLNode])

    var string: String? {
        if case .scalar(let value) = self { return value }
        return nil
    }

    var mapping: [String: YAMLNode]? {
        if case .mapping(let value) = self { return value }
        return nil
    }

    var sequence: [YAMLNode]? {
        if case .sequence(let value) = self { return value }
        return nil
    }

    func string(for key: String) -> String? {
        mapping?[key]?.string
    }

    func requiredString(_ key: String) throws -> String {
        guard let value = string(for: key), !value.isEmpty else {
            throw ConfigError.missingField(key)
        }
        return value
    }

    func int(for key: String) throws -> Int {
        guard let raw = string(for: key), let value = Int(raw) else {
            throw ConfigError.missingField(key)
        }
        return value
    }

    func bool(for key: String, default defaultValue: Bool = false) -> Bool {
        guard let raw = string(for: key) else { return defaultValue }
        switch raw.lowercased() {
        case "true", "yes", "on", "1": return true
        case "false", "no", "off", "0": return false
        default: return defaultValue
        }
    }

    func int(for key: String, default defaultValue: Int) -> Int {
        guard let raw = string(for: key), let value = Int(raw) else { return defaultValue }
        return value
    }
}

enum YAMLParser {
    private struct Line {
        var indent: Int
        var content: String
        var number: Int
    }

    static func parse(_ text: String) throws -> YAMLNode {
        let lines = tokenize(text)
        guard !lines.isEmpty else { return .mapping([:]) }
        var index = 0
        return try parseNode(lines: lines, index: &index, minIndent: 0)
    }

    private static func tokenize(_ text: String) -> [Line] {
        var result: [Line] = []
        for (offset, raw) in text.replacingOccurrences(of: "\t", with: "  ").components(separatedBy: .newlines).enumerated() {
            let (indent, body) = splitIndent(raw)
            let stripped = stripComment(body)
            if stripped.isEmpty { continue }
            if stripped == "---" || stripped == "..." { continue }
            result.append(Line(indent: indent, content: stripped, number: offset + 1))
        }
        return result
    }

    private static func splitIndent(_ line: String) -> (Int, String) {
        var count = 0
        for character in line {
            if character == " " { count += 1 } else { break }
        }
        return (count, String(line.dropFirst(count)))
    }

    private static func stripComment(_ line: String) -> String {
        var inSingle = false
        var inDouble = false
        var escaped = false
        for (index, character) in line.enumerated() {
            if escaped {
                escaped = false
                continue
            }
            if character == "\\" && inDouble {
                escaped = true
                continue
            }
            if character == "'" && !inDouble {
                inSingle.toggle()
            } else if character == "\"" && !inSingle {
                inDouble.toggle()
            } else if character == "#" && !inSingle && !inDouble {
                let cut = line.index(line.startIndex, offsetBy: index)
                return String(line[..<cut]).trimmingCharacters(in: .whitespaces)
            }
        }
        return line.trimmingCharacters(in: .whitespaces)
    }

    private static func parseNode(lines: [Line], index: inout Int, minIndent: Int) throws -> YAMLNode {
        guard index < lines.count else { return .scalar("") }
        let line = lines[index]
        if line.indent < minIndent {
            return .scalar("")
        }
        if line.content.hasPrefix("- ") || line.content == "-" {
            return try parseSequence(lines: lines, index: &index, indent: line.indent)
        }
        return try parseMapping(lines: lines, index: &index, indent: line.indent)
    }

    private static func parseSequence(lines: [Line], index: inout Int, indent: Int) throws -> YAMLNode {
        var items: [YAMLNode] = []
        while index < lines.count {
            let line = lines[index]
            if line.indent < indent { break }
            if line.indent > indent {
                throw ConfigError.yamlSyntax("unexpected indent at line \(line.number)")
            }
            guard line.content.hasPrefix("- ") || line.content == "-" else { break }
            let rest = line.content == "-"
                ? ""
                : String(line.content.dropFirst(2)).trimmingCharacters(in: .whitespaces)
            index += 1
            if rest.isEmpty {
                items.append(try parseNode(lines: lines, index: &index, minIndent: indent + 1))
            } else if rest.hasPrefix("{") || rest.hasPrefix("[") {
                items.append(try parseFlow(rest, line: line.number))
            } else if let colon = unquotedColon(in: rest), isMappingColon(rest, at: colon) {
                let key = unquote(String(rest[..<colon]).trimmingCharacters(in: .whitespaces))
                let valuePart = rest[rest.index(after: colon)...].trimmingCharacters(in: .whitespaces)
                var nested: [String: YAMLNode] = [:]
                if valuePart.isEmpty {
                    nested[key] = try parseNode(lines: lines, index: &index, minIndent: indent + 1)
                } else {
                    nested[key] = try parseInlineValue(valuePart, line: line.number)
                }
                while index < lines.count {
                    let next = lines[index]
                    if next.indent <= indent { break }
                    if next.content.hasPrefix("- ") { break }
                    let extra = try parseMapping(lines: lines, index: &index, indent: next.indent)
                    if case .mapping(let map) = extra {
                        for (mapKey, mapValue) in map { nested[mapKey] = mapValue }
                    } else {
                        break
                    }
                }
                items.append(.mapping(nested))
            } else {
                items.append(.scalar(unquote(rest)))
            }
        }
        return .sequence(items)
    }

    private static func parseMapping(lines: [Line], index: inout Int, indent: Int) throws -> YAMLNode {
        var map: [String: YAMLNode] = [:]
        while index < lines.count {
            let line = lines[index]
            if line.indent < indent { break }
            if line.indent > indent {
                throw ConfigError.yamlSyntax("unexpected indent at line \(line.number)")
            }
            if line.content.hasPrefix("- ") || line.content == "-" { break }
            guard let colon = unquotedColon(in: line.content) else {
                throw ConfigError.yamlSyntax("expected key: value at line \(line.number)")
            }
            let key = unquote(String(line.content[..<colon]).trimmingCharacters(in: .whitespaces))
            let valuePart = line.content[line.content.index(after: colon)...]
                .trimmingCharacters(in: .whitespaces)
            index += 1
            if valuePart.isEmpty {
                if index < lines.count, lines[index].indent > indent {
                    map[key] = try parseNode(lines: lines, index: &index, minIndent: lines[index].indent)
                } else {
                    map[key] = .scalar("")
                }
            } else {
                map[key] = try parseInlineValue(valuePart, line: line.number)
            }
        }
        return .mapping(map)
    }

    private static func parseInlineValue(_ raw: String, line: Int) throws -> YAMLNode {
        if raw.hasPrefix("{") || raw.hasPrefix("[") {
            return try parseFlow(raw, line: line)
        }
        return .scalar(unquote(raw))
    }

    private static func parseFlow(_ raw: String, line: Int) throws -> YAMLNode {
        var iterator = raw.makeIterator()
        return try parseFlowValue(&iterator, line: line)
    }

    private static func parseFlowValue(_ iterator: inout String.Iterator, line: Int) throws -> YAMLNode {
        skipSpaces(&iterator)
        guard let first = peek(iterator) else {
            throw ConfigError.yamlSyntax("truncated flow value at line \(line)")
        }
        if first == "{" { return try parseFlowMapping(&iterator, line: line) }
        if first == "[" { return try parseFlowSequence(&iterator, line: line) }
        return .scalar(unquote(readFlowScalar(&iterator)))
    }

    private static func parseFlowMapping(_ iterator: inout String.Iterator, line: Int) throws -> YAMLNode {
        _ = iterator.next() // {
        var map: [String: YAMLNode] = [:]
        skipSpaces(&iterator)
        if peek(iterator) == "}" {
            _ = iterator.next()
            return .mapping(map)
        }
        while true {
            skipSpaces(&iterator)
            let key = unquote(readFlowScalar(&iterator, stopAtColon: true))
            skipSpaces(&iterator)
            guard iterator.next() == ":" else {
                throw ConfigError.yamlSyntax("expected ':' in flow map at line \(line)")
            }
            map[key] = try parseFlowValue(&iterator, line: line)
            skipSpaces(&iterator)
            let separator = iterator.next()
            if separator == "}" { break }
            guard separator == "," else {
                throw ConfigError.yamlSyntax("expected ',' or '}' in flow map at line \(line)")
            }
        }
        return .mapping(map)
    }

    private static func parseFlowSequence(_ iterator: inout String.Iterator, line: Int) throws -> YAMLNode {
        _ = iterator.next() // [
        var items: [YAMLNode] = []
        skipSpaces(&iterator)
        if peek(iterator) == "]" {
            _ = iterator.next()
            return .sequence(items)
        }
        while true {
            items.append(try parseFlowValue(&iterator, line: line))
            skipSpaces(&iterator)
            let separator = iterator.next()
            if separator == "]" { break }
            guard separator == "," else {
                throw ConfigError.yamlSyntax("expected ',' or ']' in flow list at line \(line)")
            }
        }
        return .sequence(items)
    }

    private static func readFlowScalar(_ iterator: inout String.Iterator, stopAtColon: Bool = false) -> String {
        skipSpaces(&iterator)
        guard let first = peek(iterator) else { return "" }
        if first == "\"" || first == "'" {
            let quote = iterator.next()!
            var body = ""
            var escaped = false
            while let character = iterator.next() {
                if escaped {
                    body.append(character)
                    escaped = false
                    continue
                }
                if character == "\\" && quote == "\"" {
                    escaped = true
                    continue
                }
                if character == quote { break }
                body.append(character)
            }
            return body
        }
        var body = ""
        var copy = iterator
        while let character = copy.next() {
            if character == "," || character == "}" || character == "]" { break }
            if stopAtColon && character == ":" { break }
            _ = iterator.next()
            body.append(character)
        }
        return body.trimmingCharacters(in: .whitespaces)
    }

    private static func skipSpaces(_ iterator: inout String.Iterator) {
        while peek(iterator) == " " { _ = iterator.next() }
    }

    private static func peek(_ iterator: String.Iterator) -> Character? {
        var copy = iterator
        return copy.next()
    }

    /// YAML requires `:` to be followed by a space (or end of scalar) to
    /// introduce a mapping. URLs such as `https://host/path` in sequence
    /// items (`- https://…`) must stay plain scalars.
    private static func isMappingColon(_ text: String, at colon: String.Index) -> Bool {
        let after = text.index(after: colon)
        guard after < text.endIndex else { return true }
        let next = text[after]
        return next == " " || next == "\t"
    }

    private static func unquotedColon(in text: String) -> String.Index? {
        var inSingle = false
        var inDouble = false
        var depth = 0
        for index in text.indices {
            let character = text[index]
            if character == "'" && !inDouble { inSingle.toggle() }
            else if character == "\"" && !inSingle { inDouble.toggle() }
            else if !inSingle && !inDouble {
                if character == "{" || character == "[" { depth += 1 }
                if character == "}" || character == "]" { depth -= 1 }
                if character == ":" && depth == 0 { return index }
            }
        }
        return nil
    }

    private static func unquote(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.count >= 2 {
            if trimmed.hasPrefix("\"") && trimmed.hasSuffix("\"") {
                return String(trimmed.dropFirst().dropLast())
            }
            if trimmed.hasPrefix("'") && trimmed.hasSuffix("'") {
                return String(trimmed.dropFirst().dropLast())
            }
        }
        if trimmed == "~" || trimmed.lowercased() == "null" { return "" }
        return trimmed
    }
}
