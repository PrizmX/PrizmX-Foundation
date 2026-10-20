import Foundation
import Yams

extension YAMLParser {
    /// Most nodes a document may expand to. Aliases are shared in the YAML
    /// tree but copied into `YAMLNode`, so nested aliases ("billion laughs")
    /// could otherwise blow up memory in the Packet Tunnel.
    static let maxNodes = 1_000_000

    /// Parses `text` with libyaml: anchors / aliases, merge keys (`<<`),
    /// block scalars and multi-line flow collections. A document libyaml
    /// rejects is retried with the lenient subset parser, so files earlier
    /// builds imported keep importing; if both fail, libyaml's error wins.
    static func parse(_ text: String) throws -> YAMLNode {
        let source = ConfigText.strippingBOM(text)
        let composed: Node?
        do {
            composed = try Yams.compose(yaml: source)
        } catch {
            if let lenient = try? parseSubset(source) { return lenient }
            throw ConfigError.yamlSyntax(Self.describe(error))
        }
        guard let composed else { return .mapping([:]) }
        var budget = maxNodes
        return try convert(composed, budget: &budget)
    }

    private static func convert(_ node: Node, budget: inout Int) throws -> YAMLNode {
        budget -= 1
        guard budget >= 0 else {
            throw ConfigError.yamlSyntax("document expands to more than \(maxNodes) nodes")
        }
        switch node {
        case .scalar(let scalar):
            return .scalar(Self.string(of: scalar))
        case .sequence(let sequence):
            return .sequence(try sequence.map { try convert($0, budget: &budget) })
        case .mapping(let mapping):
            return .mapping(try entries(of: mapping, budget: &budget))
        case .alias:
            // `compose` resolves aliases to their anchored node; an
            // unresolved one carries no value.
            return .scalar("")
        }
    }

    /// Explicit keys win over merged ones; among merged mappings
    /// (`<<: [*a, *b]`) the earlier one wins, as in YAML 1.1.
    private static func entries(of mapping: Node.Mapping, budget: inout Int) throws -> [String: YAMLNode] {
        var explicit: [String: YAMLNode] = [:]
        var merged: [String: YAMLNode] = [:]
        for (key, value) in mapping {
            guard case .scalar(let keyScalar) = key else { continue }
            if keyScalar.style == .plain, keyScalar.string == "<<" {
                let sources: [Node]
                switch value {
                case .mapping: sources = [value]
                case .sequence(let list): sources = Array(list)
                default: sources = []
                }
                for source in sources {
                    guard case .mapping(let inner) = source else { continue }
                    for (name, item) in try entries(of: inner, budget: &budget) where merged[name] == nil {
                        merged[name] = item
                    }
                }
                continue
            }
            explicit[keyScalar.string] = try convert(value, budget: &budget)
        }
        return merged.merging(explicit) { _, explicit in explicit }
    }

    /// Plain `~` / `null` is empty, as the subset parser reads it.
    private static func string(of scalar: Node.Scalar) -> String {
        if scalar.style == .plain {
            let value = scalar.string
            if value == "~" || value.lowercased() == "null" { return "" }
        }
        return scalar.string
    }

    private static func describe(_ error: Error) -> String {
        if let yaml = error as? YamlError {
            // The default description quotes the offending source line,
            // which may hold a password; keep the problem and position.
            switch yaml {
            case .scanner(_, let problem, let mark, _),
                 .parser(_, let problem, let mark, _),
                 .composer(_, let problem, let mark, _):
                return "\(problem) at line \(mark.line)"
            default:
                break
            }
        }
        return "invalid YAML"
    }
}
