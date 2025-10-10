const std = @import("std");
const expect = std.testing.expect;
const use_utf8 = @import("options").use_utf8;

const StringFlags = packed struct(u32) {
    case_insensitive: bool = false,
    charset_scan: bool = false,
    _padding: u30 = 0,
};

const Codepoint = if (use_utf8) u21 else u8;
const Uppercase = if (use_utf8) struct {
    const uucode = @import("uucode");
    const Self = @This();

    const Value = union(enum) { cp: u21, cp_slice: []const u21 };
    value: Value,

    pub fn from(cp: u21, enabled: bool) Self {
        if (enabled) {
            var buffer: [1]u21 = undefined;
            const uppercase = uucode.get(.uppercase_mapping, cp).with(&buffer, cp);

            if (uppercase[0..1] == &buffer) {
                // using buffer as backing
                return .{
                    .value = .{ .cp = uppercase[0] },
                };
            } else {
                return .{
                    .value = .{ .cp_slice = uppercase },
                };
            }
        }

        return .{ .value = Value{ .cp = cp } };
    }

    pub fn cmp(self: Self, other: Self) std.math.Order {
        switch (self.value) {
            .cp => |self_cp| {
                switch (other.value) {
                    .cp => |other_cp| {
                        return std.math.order(self_cp, other_cp);
                    },
                    .cp_slice => |other_slice| {
                        return std.mem.order(u21, &.{self_cp}, other_slice);
                    },
                }
            },
            .cp_slice => |self_slice| {
                switch (other.value) {
                    .cp => |other_cp| {
                        return std.mem.order(u21, self_slice, &.{other_cp});
                    },
                    .cp_slice => |other_slice| {
                        return std.mem.order(u21, self_slice, other_slice);
                    },
                }
            },
        }
    }
} else struct {
    const Self = @This();

    value: u8,

    pub fn from(cp: u8, enabled: bool) Self {
        if (enabled and cp >= 'a' and cp <= 'z') {
            return .{ .value = cp & 0x5f };
        }

        return .{ .value = cp };
    }

    pub fn cmp(self: Self, other: Self) std.math.Order {
        return std.math.order(self.value, other.value);
    }
};

const StringIterator = blk: {
    if (use_utf8) {
        const uucode = @import("uucode");
        break :blk uucode.utf8.Iterator;
    } else {
        // dummy iterator for ASCII
        break :blk struct {
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
    }
};

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

    var pattern_iter = StringIterator.init(pattern);

    const to_check = Uppercase.from(cp, flags.case_insensitive);

    if (flags.charset_scan) {
        if (pattern_iter.peek() == '^') {
            inverted = true;
            _ = pattern_iter.next(); // advance iterator
        }

        // Special case. If the first char is ']', it is part of the set
        if (pattern_iter.peek() == ']') {
            if (to_check.cmp(Uppercase.from(']', flags.case_insensitive)) == .eq) {
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

        var check_against: ?Uppercase = null;

        // Exact match
        if (pattern_cp == '\\') {
            if (pattern_iter.next()) |unwrapped| {
                check_against = Uppercase.from(unwrapped, flags.case_insensitive);
            }
        } else {
            // Is this a range? e.g. [a-z]
            if (pattern_iter.peek() == '-') {
                const start_cp = Uppercase.from(pattern_cp, flags.case_insensitive);
                _ = pattern_iter.next(); // skip -
                const end_cp = Uppercase.from(
                    pattern_iter.next() orelse continue,
                    flags.case_insensitive,
                );

                // Handle reversed range too
                if ((to_check.cmp(start_cp).compare(.gte) and to_check.cmp(end_cp).compare(.lte)) or
                    (to_check.cmp(end_cp).compare(.gte) and to_check.cmp(start_cp).compare(.lte)))
                {
                    found_match = true;
                }
                continue;
            }

            check_against = Uppercase.from(pattern_cp, flags.case_insensitive);
        }

        if (check_against != null and check_against.?.cmp(to_check) == .eq) {
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
pub fn glob_match(pattern: []const u8, string: []const u8, case_insensitive: bool) bool {
    var pattern_iter = StringIterator.init(pattern);
    var string_iter = StringIterator.init(string);

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

                while (string_iter.i < string.len) {
                    // Recursive call - Does the remaining pattern match anywhere?
                    if (glob_match(pattern[pattern_iter.i..], string[string_iter.i..], case_insensitive)) {
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
                var check_against: Uppercase = undefined;
                if (pattern_cp == '\\') {
                    check_against = Uppercase.from(
                        pattern_iter.next() orelse '\\',
                        case_insensitive,
                    );
                } else {
                    check_against = Uppercase.from(pattern_cp, case_insensitive);
                }

                const to_check = Uppercase.from(
                    string_iter.next() orelse return false,
                    case_insensitive,
                );
                if (check_against.cmp(to_check) != .eq) return false;
            },
        }

        if (string_iter.i >= string.len) {
            // keep advancing until it's not an asterisk
            while (pattern_iter.peek() == '*') {
                _ = pattern_iter.next();
            }
        }
    }

    // did we reach the end of both?
    return (string_iter.i >= string.len) and (pattern_iter.i >= pattern.len);
}

test "glob match" {
    try expect(glob_match("any?hing", "ANYTHING", true));
}
