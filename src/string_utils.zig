const std = @import("std");
const unicode = std.unicode;
const expect = std.testing.expect;

const StringFlags = packed struct(u32) {
    case_insensitive: bool = false,
    charset_scan: bool = false,
    _padding: u30 = 0,
};

pub fn to_uppercase(codepoint: u21, enabled: bool) u21 {
    if (enabled) {
        if (codepoint >= 'a' and codepoint <= 'z') {
            return codepoint & 0x5f;
        }
    }

    return codepoint;
}

pub fn ascii_compare(codepoint_slice: ?[]const u8, char: u8) bool {
    if (codepoint_slice) |unwrapped| {
        return unwrapped.len == 1 and unwrapped[0] == char;
    }

    return false;
}

/// pattern points to a string like "[^a-z\ub5]"
///
/// The pattern may contain trailing chars, which are ignored.
///
/// The pattern is matched against unicode char 'c'.
///
/// If (flags & JIM_NOCASE), case is ignored when matching.
/// If (flags & JIM_CHARSET_SCAN), the considers ^ and ] special at the start
/// of the charset, per scan, rather than glob/string match.
///
/// If the unicode char 'c' matches that set, returns a pointer to the ']' character,
/// or the null character if the ']' is missing.
///
/// Returns null on no match.
pub fn charset_match(pattern: []const u8, codepoint: u21, flags: StringFlags) ?usize {
    // inverted = if it starts with ^
    var inverted = false;
    var found_match = false;

    var pattern_iter = unicode.Utf8View.initUnchecked(pattern).iterator();

    const to_check = to_uppercase(codepoint, flags.case_insensitive);

    if (flags.charset_scan) {
        if (ascii_compare(pattern_iter.peek(1), '^')) {
            inverted = true;
            _ = pattern_iter.nextCodepoint(); // advance iterator
        }

        // Special case. If the first char is ']', it is part of the set
        if (ascii_compare(pattern_iter.peek(1), ']')) {
            if (to_check == ']') {
                found_match = true;
            }
            _ = pattern_iter.nextCodepoint(); // advance iterator
        }
    }

    while (pattern_iter.nextCodepoint()) |pattern_codepoint| {
        if (pattern_codepoint == ']') {
            pattern_iter.i -= 1;
            break;
        }

        var check_against: ?u21 = null;

        // Exact match
        if (pattern_codepoint == '\\') {
            if (pattern_iter.nextCodepoint()) |unwrapped| {
                check_against = to_uppercase(unwrapped, flags.case_insensitive);
            }
        } else {
            // Is this a range? e.g. [a-z]
            if (ascii_compare(pattern_iter.peek(1), '-')) {
                var start_codepoint = pattern_codepoint;
                _ = pattern_iter.nextCodepointSlice(); // skip -
                var end_codepoint = pattern_iter.nextCodepoint() orelse continue;

                start_codepoint = to_uppercase(start_codepoint, flags.case_insensitive);
                end_codepoint = to_uppercase(end_codepoint, flags.case_insensitive);

                // Handle reversed range too
                if ((to_check >= start_codepoint and to_check <= end_codepoint) or
                    (to_check >= end_codepoint and to_check <= start_codepoint))
                {
                    found_match = true;
                }
                continue;
            }

            check_against = pattern_codepoint;
        }

        if (check_against != null and check_against.? == codepoint) {
            found_match = true;
        }
    }

    if (inverted) {
        found_match = !found_match;
    }

    return if (found_match) pattern_iter.i else null;
}

test "charset_match" {
    try expect(charset_match("a-z", 'c', .{}) == 3);
    try expect(charset_match("a-z", 'C', .{}) == null);
    try expect(charset_match("a-z", 'C', .{ .case_insensitive = true }) == 3);
    try expect(charset_match("a-", 'c', .{}) == null);
    try expect(charset_match("", 'c', .{}) == null);
    try expect(charset_match("^", '^', .{}) == 1);
    try expect(charset_match("^", '^', .{ .charset_scan = true }) == 1);
    try expect(charset_match("^a", 'a', .{ .charset_scan = true }) == null);
}

/// Glob-style pattern matching.
///
/// Note: string *must* be valid UTF-8 sequences.
pub fn glob_match(pattern: []const u8, string: []const u8, case_insensitive: bool) bool {
    var pattern_iter = unicode.Utf8View.initUnchecked(pattern).iterator();
    var string_iter = unicode.Utf8View.initUnchecked(string).iterator();

    while (pattern_iter.nextCodepoint()) |pattern_codepoint| {
        switch (pattern_codepoint) {
            '*' => {
                // keep advancing until it's not an asterisk
                while (ascii_compare(pattern_iter.peek(1), '*')) {
                    _ = pattern_iter.nextCodepointSlice(); // advance iterator
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
                    _ = string_iter.nextCodepointSlice(); // advance iterator
                }

                return false; // no match
            },
            '?' => {
                _ = string_iter.nextCodepointSlice(); // advance iterator
            },
            '[' => {
                const to_check = string_iter.nextCodepoint() orelse return false;
                if (pattern_iter.i >= pattern.len) break;

                const result = charset_match(
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
                var check_against: u21 = undefined;
                if (pattern_codepoint == '\\') {
                    check_against = to_uppercase(
                        pattern_iter.nextCodepoint() orelse return false,
                        case_insensitive,
                    );
                } else {
                    check_against = to_uppercase(pattern_codepoint, case_insensitive);
                }

                const to_check = to_uppercase(
                    string_iter.nextCodepoint() orelse return false,
                    case_insensitive,
                );
                if (check_against != to_check) {
                    return false;
                }
            },
        }

        if (string_iter.i >= string.len) {
            // keep advancing until it's not an asterisk
            while (ascii_compare(pattern_iter.peek(1), '*')) {
                _ = pattern_iter.nextCodepointSlice();
            }
        }
    }

    // did we reach the end of both?
    return (string_iter.i >= string.len) and (pattern_iter.i >= pattern.len);
}

test "glob match" {
    try expect(glob_match("any?hing", "ANYTHING", true));
}

pub fn utf8_compare()
