import Foundation

/// Parser and matcher for standard 5-field (minute..weekday) and Surge/Stash
/// 6-field (second minute..weekday) cron expressions.
public struct CronSchedule: Sendable, Equatable, Hashable {
    public enum ParseError: Error, Equatable, Sendable, LocalizedError {
        case invalidFieldCount(Int)
        case invalidField(String)

        public var errorDescription: String? {
            switch self {
            case .invalidFieldCount(let count):
                "Cron expression expects 5 or 6 fields (got \(count))."
            case .invalidField(let field):
                "Invalid cron field: \(field)"
            }
        }
    }

    public let seconds: Set<Int>?
    public let minutes: Set<Int>
    public let hours: Set<Int>
    public let daysOfMonth: Set<Int>
    public let months: Set<Int>
    /// 0...6 where 0 = Sunday (7 is also accepted as Sunday on parse).
    public let daysOfWeek: Set<Int>
    private let dayOfMonthWildcard: Bool
    private let dayOfWeekWildcard: Bool

    public static func parse(_ expression: String) throws -> CronSchedule {
        let fields = expression
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .split(whereSeparator: { $0.isWhitespace })
            .map(String.init)
        guard fields.count == 5 || fields.count == 6 else {
            throw ParseError.invalidFieldCount(fields.count)
        }

        let offset = fields.count == 6 ? 1 : 0
        let seconds: Set<Int>? = offset == 1 ? try parseField(fields[0], range: 0...59) : nil
        let minutes = try parseField(fields[offset], range: 0...59)
        let hours = try parseField(fields[offset + 1], range: 0...23)
        let domField = fields[offset + 2]
        let dom = try parseField(domField, range: 1...31)
        let months = try parseField(fields[offset + 3], range: 1...12)
        let dowField = fields[offset + 4]
        let rawDow = try parseField(dowField, range: 0...7)
        let dow = Set(rawDow.map { $0 == 7 ? 0 : $0 })

        return CronSchedule(
            seconds: seconds,
            minutes: minutes,
            hours: hours,
            daysOfMonth: dom,
            months: months,
            daysOfWeek: dow,
            dayOfMonthWildcard: domField == "*" || domField == "?",
            dayOfWeekWildcard: dowField == "*" || dowField == "?"
        )
    }

    /// Evaluates whether `date` matches this schedule. For 5-field expressions,
    /// seconds are ignored; for 6-field expressions, `ignoreSeconds` may be set
    /// to `true` by minute-level schedulers (matching if any second in the minute
    /// is enabled).
    public func matches(
        _ date: Date,
        calendar: Calendar = .current,
        ignoreSeconds: Bool = false
    ) -> Bool {
        let comps = calendar.dateComponents([.second, .minute, .hour, .day, .month, .weekday], from: date)
        guard let minute = comps.minute,
              let hour = comps.hour,
              let day = comps.day,
              let month = comps.month,
              let appleWeekday = comps.weekday
        else { return false }

        if !ignoreSeconds, let seconds, let second = comps.second, !seconds.contains(second) {
            return false
        }
        guard minutes.contains(minute), hours.contains(hour), months.contains(month) else {
            return false
        }
        // Calendar.weekday: 1 = Sunday ... 7 = Saturday -> 0 = Sunday ... 6 = Saturday.
        let cronWeekday = appleWeekday - 1
        let domMatch = daysOfMonth.contains(day)
        let dowMatch = daysOfWeek.contains(cronWeekday)
        if dayOfMonthWildcard && dayOfWeekWildcard {
            return true
        } else if dayOfMonthWildcard {
            return dowMatch
        } else if dayOfWeekWildcard {
            return domMatch
        } else {
            return domMatch || dowMatch
        }
    }

    private static func parseField(_ field: String, range: ClosedRange<Int>) throws -> Set<Int> {
        if field == "*" || field == "?" {
            return Set(range)
        }
        var result = Set<Int>()
        for part in field.split(separator: ",", omittingEmptySubsequences: false) {
            let segment = String(part)
            guard !segment.isEmpty else { throw ParseError.invalidField(field) }
            let stepParts = segment.split(separator: "/", omittingEmptySubsequences: false)
            guard stepParts.count <= 2 else { throw ParseError.invalidField(field) }

            let step: Int
            if stepParts.count == 2 {
                guard let parsed = Int(stepParts[1]), parsed > 0 else {
                    throw ParseError.invalidField(field)
                }
                step = parsed
            } else {
                step = 1
            }

            let base = String(stepParts[0])
            let subRange: ClosedRange<Int>
            if base == "*" || base == "?" {
                subRange = range
            } else if base.contains("-") {
                let bounds = base.split(separator: "-", omittingEmptySubsequences: false)
                guard bounds.count == 2,
                      let low = Int(bounds[0]),
                      let high = Int(bounds[1]),
                      low <= high,
                      range.contains(low),
                      range.contains(high)
                else {
                    throw ParseError.invalidField(field)
                }
                subRange = low...high
            } else {
                guard let value = Int(base), range.contains(value) else {
                    throw ParseError.invalidField(field)
                }
                if stepParts.count == 2 {
                    subRange = value...range.upperBound
                } else {
                    subRange = value...value
                }
            }

            var current = subRange.lowerBound
            while current <= subRange.upperBound {
                result.insert(current)
                current += step
            }
        }
        guard !result.isEmpty else { throw ParseError.invalidField(field) }
        return result
    }
}
