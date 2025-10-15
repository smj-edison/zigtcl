const std = @import("std");
const expect = std.testing.expect;
const expectEqual = std.testing.expectEqual;

const uucode = @import("uucode");

const use_utf8 = @import("options").use_utf8;

const StringFlags = packed struct(u32) {
    case_insensitive: bool = false,
    charset_scan: bool = false,
    _padding: u30 = 0,
};

const Codepoint = if (use_utf8) u21 else u8;

fn toUppercaseUtf8(cp: u21) u21 {
    return uucode.get(.simple_uppercase_mapping, cp) orelse cp;
}

const toUpper = if (use_utf8) toUppercaseUtf8 else std.ascii.toUpper;

/// Conditional uppercase
fn condUpper(cp: Codepoint, enabled: bool) Codepoint {
    if (enabled) {
        return toUpper(cp);
    } else {
        return cp;
    }
}

test "Conditional uppercase" {
    try expectEqual('A', condUpper('a', true));
    try expectEqual('a', condUpper('a', false));
    try expectEqual('/', condUpper('/', true));
}

const AsciiIterator = struct {
    bytes: []const u8,
    i: usize = 0,

    const Self = @This();

    pub fn init(bytes: []const u8) Self {
        return .{
            .bytes = bytes,
        };
    }

    pub fn next(self: *Self) ?u8 {
        if (self.i >= self.bytes.len) return null;

        const cp = self.bytes[self.i];
        self.i += 1;

        return cp;
    }

    pub fn peek(self: Self) ?u8 {
        var it = self;
        return it.next();
    }
};

/// Iterate over codepoints
pub const Iterator = if (use_utf8) uucode.utf8.Iterator else AsciiIterator;

/// lexographical comparision of codepoints
pub fn compare(a: []const u8, b: []const u8) std.math.Order {
    var a_iter = Iterator.init(a);
    var b_iter = Iterator.init(b);

    while (true) {
        const a_cp = a_iter.next();
        const b_cp = b_iter.next();

        if (a_cp != null and b_cp != null) {
            const order = std.math.order(u21, a_cp.?, b_cp.?);
            if (order != .eq) return order;
        } else {
            if (a_cp == null and b_cp != null) return .lt;
            if (a_cp == null and b_cp == null) return .eq;
            if (a_cp != null and b_cp == null) return .gt;
        }
    }

    return .eq;
}

pub fn cpIndexUtf8(str: []const u8, index: usize) ?usize {
    if (index >= str.len) return null;

    var iter = Iterator.init(str);

    var cp_index: usize = 0;
    while (cp_index < index) {
        _ = iter.next() orelse return null;
        cp_index += 1;
    }

    return iter.i;
}

pub fn cpIndexAscii(str: []const u8, index: usize) ?usize {
    if (index >= str.len) return null;
    return index;
}

/// get the byte index based on codepoint index
const cpIndex = if (use_utf8) cpIndexUtf8 else cpIndexAscii;

test "codepoint index" {
    try expectEqual(cpIndex("hello", 3), 3);
    if (use_utf8) try expectEqual(cpIndex("⇧hello", 3), 5);
}

pub fn strlenUtf8(str: []const u8) usize {
    var iter = Iterator.init(str);
    var count = 0;

    while (iter.next()) {
        count += 1;
    }

    return count;
}

pub fn strlenAscii(str: []const u8) usize {
    return str.len;
}

/// get the string length in codepoints
const strlen = if (use_utf8) strlenUtf8 else strlenAscii;

/// pattern points to a string like "[^a-z\ub5]"
///
/// The pattern may contain trailing chars, which are ignored.
///
/// The pattern is matched against unicode char 'c'.
///
/// If StringFlags.case_insensitive, case is ignored when matching.
/// If StringFlags.charset_scan, the considers ^ and ] special at the start
/// of the charset, per scan, rather than glob/string match.
///
/// If the unicode char 'c' matches that set, returns a pointer to the ']' character,
/// or the null character if the ']' is missing.
///
/// Returns null on no match.
pub fn charsetMatch(pattern: []const u8, cp: Codepoint, flags: StringFlags) ?usize {
    // inverted = if it starts with ^
    var inverted = false;
    var found_match = false;

    var pattern_iter = Iterator.init(pattern);

    const to_check = condUpper(cp, flags.case_insensitive);

    if (flags.charset_scan) {
        if (pattern_iter.peek() == '^') {
            inverted = true;
            _ = pattern_iter.next(); // advance iterator
        }

        // Special case. If the first char is ']', it is part of the set
        if (pattern_iter.peek() == ']') {
            if (cp == ']') {
                found_match = true;
            }
            _ = pattern_iter.next(); // advance iterator
        }
    }

    while (pattern_iter.next()) |pattern_cp| {
        if (pattern_cp == ']') {
            pattern_iter.i -= 1;
            break;
        }

        var check_against: ?Codepoint = null;

        // Exact match
        if (pattern_cp == '\\') {
            if (pattern_iter.next()) |unwrapped| {
                check_against = condUpper(unwrapped, flags.case_insensitive);
            }
        } else {
            // Is this a range? e.g. [a-z]
            if (pattern_iter.peek() == '-') {
                const start_cp = condUpper(pattern_cp, flags.case_insensitive);
                _ = pattern_iter.next(); // skip -
                const end_cp = condUpper(
                    pattern_iter.next() orelse continue,
                    flags.case_insensitive,
                );

                // Handle reversed range too
                if ((to_check >= start_cp and to_check <= end_cp) or
                    (to_check >= end_cp and to_check <= start_cp))
                {
                    found_match = true;
                }
                continue;
            }

            check_against = condUpper(pattern_cp, flags.case_insensitive);
        }

        if (check_against != null and check_against == to_check) {
            found_match = true;
        }
    }

    if (inverted) {
        found_match = !found_match;
    }

    return if (found_match) pattern_iter.i else null;
}

test "charsetMatch" {
    try expect(charsetMatch("a-z", 'c', .{}) == 3);
    try expect(charsetMatch("a-z", 'C', .{}) == null);
    try expect(charsetMatch("a-z", 'C', .{ .case_insensitive = true }) == 3);
    try expect(charsetMatch("a-", 'c', .{}) == null);
    try expect(charsetMatch("", 'c', .{}) == null);
    try expect(charsetMatch("^", '^', .{}) == 1);
    try expect(charsetMatch("^", '^', .{ .charset_scan = true }) == 1);
    try expect(charsetMatch("^a", 'a', .{ .charset_scan = true }) == null);
}

/// Glob-style pattern matching.
///
/// Note: string *must* be valid UTF-8 sequences.
pub fn globMatch(pattern: []const u8, str: []const u8, case_insensitive: bool) bool {
    var pattern_iter = Iterator.init(pattern);
    var string_iter = Iterator.init(str);

    while (pattern_iter.next()) |pattern_cp| {
        switch (pattern_cp) {
            '*' => {
                // keep advancing until it's not an asterisk
                while (pattern_iter.peek() == '*') {
                    _ = pattern_iter.next(); // advance iterator
                }

                if (pattern_iter.i >= pattern.len) {
                    // guaranteed match, as there's nothing after the asterisk to check
                    return true;
                }

                while (string_iter.i < str.len) {
                    // Recursive call - Does the remaining pattern match anywhere?
                    if (globMatch(pattern[pattern_iter.i..], str[string_iter.i..], case_insensitive)) {
                        return true; // match
                    }
                    _ = string_iter.next(); // advance iterator
                }

                return false; // no match
            },
            '?' => {
                _ = string_iter.next(); // advance iterator
            },
            '[' => {
                const to_check = string_iter.next() orelse return false;
                if (pattern_iter.i >= pattern.len) break;

                const result = charsetMatch(
                    pattern[pattern_iter.i..],
                    to_check,
                    .{ .case_insensitive = case_insensitive },
                );
                if (result == null) return false;

                const bracket_length = result.?;
                pattern_iter.i += bracket_length;
                if (pattern_iter.i >= pattern.len) break;
            },
            else => {
                var check_against: Codepoint = undefined;
                if (pattern_cp == '\\') {
                    check_against = condUpper(
                        pattern_iter.next() orelse '\\',
                        case_insensitive,
                    );
                } else {
                    check_against = condUpper(pattern_cp, case_insensitive);
                }

                const to_check = condUpper(
                    string_iter.next() orelse return false,
                    case_insensitive,
                );
                if (check_against != to_check) return false;
            },
        }

        if (string_iter.i >= str.len) {
            // keep advancing until it's not an asterisk
            while (pattern_iter.peek() == '*') {
                _ = pattern_iter.next();
            }
        }
    }

    // did we reach the end of both?
    return (string_iter.i >= str.len) and (pattern_iter.i >= pattern.len);
}

test "glob match" {
    try expect(globMatch("any?hing", "ANYTHING", true));
    try expect(!globMatch("any?hing", "ANYTHING", false));
}

pub fn findFirstOccurrence(searching_for: []const u8, searching_in: []const u8, cp_index: usize) ?usize {
    if (searching_for.len > searching_in.len or cp_index > searching_in.len) {
        return null;
    }

    var searching_in_iter = Iterator.init(searching_in);
    searching_in_iter.i = cpIndex(searching_in, cp_index) orelse return null;

    while (true) : (_ = searching_in_iter.next()) {
        _ = searching_in_iter.peek() orelse return null;
        if (searching_in_iter.bytes.len - searching_in_iter.i < searching_for.len) {
            return null;
        }

        const searching_in_slice =
            searching_in[searching_in_iter.i .. searching_in_iter.i + searching_for.len];
        if (std.mem.eql(u8, searching_for, searching_in_slice)) {
            return searching_in_iter.i;
        }
    }

    return null;
}

test "Find first occurrence" {
    try expectEqual(findFirstOccurrence("world", "hello world world", 0), 6);
    try expectEqual(findFirstOccurrence("wold", "hello world", 0), null);
    try expectEqual(findFirstOccurrence("world", "hello world", 6), 6);
    try expectEqual(findFirstOccurrence("world", "hello world", 7), null);
}

pub fn findLastOccurrence(searching_for: []const u8, searching_in: []const u8) ?usize {
    if (searching_for.len > searching_in.len) {
        return null;
    }

    var idx = searching_in.len - searching_for.len;
    while (true) {
        if (std.mem.eql(u8, searching_for, searching_in[idx .. idx + searching_for.len])) {
            return idx;
        }

        if (idx == 0) return null;
        idx -= 1;
    }
}

test "Find last occurrence" {
    try expectEqual(findLastOccurrence("world", "hello world world"), 12);
    try expectEqual(findLastOccurrence("world", "hello"), null);
}
