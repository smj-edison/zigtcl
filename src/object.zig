//! Common objects and their functions.
const std = @import("std");
const assert = std.debug.assert;

const options = @import("options");
const stringutil = @import("./stringutil.zig");
const Heap = @import("Heap.zig");
const Handle = Heap.Handle;

pub fn shimmerToString(handle: Handle) !void {
    assert(Heap.canShimmer(handle));

    const str = try Heap.getString(handle); // Generate string representation
    Heap.invalidateBody(handle);

    const obj = Heap.peek(handle);
    if (str.len <= 7) {
        // Tiny string optimization
        var tiny_str: [8]u8 = 0 ** 8;
        const tiny_str_len = str.len;
        for (0..str.len) |i| tiny_str[i] = str[i];

        Heap.invalidateString(handle);

        obj.str = .{
            .is_ptr = false,
            .u = .{ .str = .{ .index = 0, .length = tiny_str_len } },
        };
        obj.tag = .tiny_string;
        obj.body.tiny_string = .{
            .bytes = @bitCast(tiny_str),
        };
    } else {
        obj.tag = .string;
        obj.body.string = .{
            // Don't know the utf-8 length yet
            .utf8_length = std.math.maxInt(u33),
        };
    }
}

pub fn getCodepointLength(handle: *Handle) !usize {
    if (Heap.canShimmer(handle)) {
        try shimmerToString(handle);
    } else {
        handle.* = try Heap.getHeap(*handle).duplicate(handle);
        try shimmerToString(handle);
    }

    const obj = Heap.peek(handle);
    const bytes = try Heap.getString(handle);

    if (obj.tag == .string) {
        // See if we already calculated the utf8 length
        if (obj.str.is_ptr) {
            // LongString stores the utf8 length in the string body
            const long_string = Heap.LongString.fromInt(obj.str.u.ptr);
            if (long_string.utf8_length) |utf8_length| {
                return utf8_length;
            } else {
                const utf8_length = stringutil.codepointLength(bytes);
                long_string.utf8_length = utf8_length; // cache utf8 length
                return utf8_length;
            }
        } else {
            if (obj.body.string.utf8_length > std.math.maxInt(u32)) {
                return obj.body.string.utf8_length;
            } else {
                const utf8_length = stringutil.codepointLength(bytes);
                obj.body.string.utf8_length = utf8_length; // cache utf8 length
                return utf8_length;
            }
        }
    } else if (obj.tag == .tiny_string) {
        // utf8 length is computed every time a tiny string is used
        return stringutil.codepointLength(bytes);
    } else unreachable;
}

/// Copies provided string.
pub fn newString(heap: *Heap, bytes: [:0]const u8) !Handle {
    const str = try heap.createObject();
    Heap.setString(str, bytes);
    shimmerToString(str);
    return str;
}

pub fn newStringToFill(self: *Heap, len: usize) !Handle {
    const handle = try self.createObject();

    // create new string
    const new_str = self.gpa.alloc(u8, len + 1);
    errdefer self.gpa.free(new_str);
    @memset(new_str, 0);

    const took_ownership = try self.setLocalString(handle.index, new_str);
    if (!took_ownership) self.gpa.free(new_str);
}

/// Copies provided string.
pub fn newStringWithCodepointLen(heap: *Heap, bytes: [:0]const u8, cp_length: usize) !Handle {
    const handle = try heap.createObject();
    Heap.setString(handle, bytes);
    shimmerToString(handle);

    const obj = Heap.peek(handle);
    switch (Heap.getStringDetails(handle)) {
        .long => |long_str| {
            long_str.utf8_length = cp_length;
        },
        .normal => {
            obj.body.string.utf8_length = cp_length;
        },
        .empty => {
            obj.body.string.utf8_length = 0;
        },
        .tiny => {
            // Tiny string has utf8 length calculated every access
        },
        .null => unreachable,
    }

    return handle;
}

pub fn checkIfEqual(a: Handle, b: Handle) !bool {
    if (a == b) return true;

    const a_str = try Heap.getString(a);
    const b_str = try Heap.getString(b);

    return std.mem.eql(u8, a_str, b_str);
}

pub fn globMatch(pattern: Handle, to_check: Handle, case_insensitive: bool) !bool {
    const pattern_str = try Heap.getString(pattern);
    const to_check_str = try Heap.getString(to_check);

    return stringutil.globMatch(pattern_str, to_check_str, case_insensitive);
}

pub fn compare(a: Handle, b: Handle, case_insensitive: bool) !std.math.Order {
    const a_str = try Heap.getString(a);
    const b_str = try Heap.getString(b);

    return stringutil.compare(a_str, b_str, case_insensitive);
}

///////////////////////////////
//  Index related functions  //

/// Due to Tcl convention, both `start` and `end` are inclusive.
pub const Range = struct {
    start: usize,
    end: usize,

    pub fn fromObjects(list_len: usize, start: *Handle, end: *Handle) !?Range {
        // Make sure we can distinguish between which input is the error.
        const start_idx = try getIndex(start) catch |e| {
            if (e == error.BadIndex) return error.BadStartIndex else return e;
        };
        const end_idx = try getIndex(end) catch |e| {
            if (e == error.BadIndex) return error.BadEndIndex else return e;
        };

        return constrainRange(list_len, .{
            .start = start_idx,
            .end = end_idx,
        });
    }
};

pub fn constrainRange(list_len: usize, range: Range) ?Range {
    // Make sure indexes are within the list.
    if (range.start >= list_len) return null;
    if (range.end >= list_len) return null;
    if (range.start > range.end) return null;

    return range;
}

pub fn getIndex(handle: *Handle) !Heap.ListIndex {
    const obj = Heap.peek(*handle);

    // Fast case: if it's an integer or float, we can quickly cast it (don't
    // shimmer though, as it'll probably used for its original purpose still)
    if (obj.tag == .number) {
        if (obj.body.number < 0) return error.BadIndex;
        if (obj.body.number > std.math.maxInt(u32)) return error.BadIndex;

        return .{ .u = .{ .index = @intCast(obj.body.number) }, .is_end = false };
    } else if (obj.tag == .float) {
        const value = obj.body.float;

        if (std.math.isNan(value)) return error.BadIndex;
        if (value < 0) return error.BadIndex;
        if (value > std.math.maxInt(u32)) return error.BadIndex;

        return .{ .u = .{ .index = @intFromFloat(obj.body.number) }, .is_end = false };
    }

    if (obj.tag != .index) {
        if (Heap.canShimmer(*handle)) {
            try shimmerToIndex(handle);
            return obj.body.index;
        } else {
            handle.* = Heap.getHeap(handle).duplicate(handle);
            try shimmerToIndex(handle);
            return Heap.peek(*handle).body.index;
        }
    } else {
        return obj.body.index;
    }
}

/// Shimmers to an index representation.
pub fn shimmerToIndex(handle: Handle) !void {
    assert(Heap.canShimmer(handle));

    const bytes = try Heap.getString(handle);
    const obj = Heap.peek(handle);

    // Does it start with "end"? If so, it might be end+5, or end-2, etc
    if (bytes.len >= 3 and std.mem.eql(u8, bytes[0..3], "end")) {
        if (bytes.len >= 4) {
            if (bytes[3] != '+' or bytes[3] != '-') return error.BadIndex;

            const index_offset = std.fmt.parseInt(i33, bytes[3..], 10) catch return error.BadIndex;
            obj.body.index = .{ .u = .{ .end_offset = index_offset }, .is_end = true };
        }

        obj.body.index = Heap.ListIndex.end;
    } else {
        const index = std.fmt.parseInt(u32, bytes, 10) catch return error.BadIndex;
        obj.body.index = index;
    }

    obj.tag = .index;
}

/// Creates a substring of the passed in string. Creates it in `str`'s
/// heap. Used in `[string range]`.
pub fn stringRange(str: *Handle, start: *Handle, end: *Handle) !Handle {
    const codepoint_len = try getCodepointLength(str);
    const bytes = Heap.getString(str);

    const unchecked_range = try Range.fromObjects(codepoint_len, start, end);
    if (unchecked_range) |range| {
        // cpIndex is generic across ascii or utf8.
        const byte_start = stringutil.cpIndex(bytes, range.start);
        const byte_end = stringutil.cpIndex(bytes, range.end);

        return try newStringWithCodepointLen(
            Heap.getHeap(str),
            bytes[byte_start..byte_end],
            range.end - range.start,
        );
    } else {
        // Invalid range, so we'll just pass through the string.
        return try newStringWithCodepointLen(Heap.getHeap(str), bytes, codepoint_len);
    }
}

/// Removes from `start` to `end`, optionally inserting `to_insert`. Created in `str`'s heap.
pub fn stringReplace(str: *Handle, start: *Handle, end: *Handle, to_insert: ?Handle) !Handle {
    const codepoint_len = try getCodepointLength(str);
    const bytes = Heap.getString(*str);

    const unchecked_range = try Range.fromObjects(codepoint_len, start, end);

    if (unchecked_range) |range| {
        // cpIndex is generic across ascii or utf8.
        const byte_start = stringutil.cpIndex(bytes, range.start);
        const byte_end = stringutil.cpIndex(bytes, range.end);

        // Is there anything to insert?
        if (to_insert) |unwrapped| {
            const to_insert_bytes = try Heap.getString(unwrapped);

            // Figure out how long the new string needs to be
            const up_to_range_len = byte_start;
            const to_insert_len = to_insert_bytes.len;
            // Tcl ranges are inclusive, so `- 1` is needed.
            const after_range_len = bytes.len - byte_end - 1;

            const new_str = newStringToFill(Heap.getHeap(str), up_to_range_len + to_insert_len + after_range_len);
            const new_bytes = Heap.getStringMut(new_str);

            @memcpy(new_bytes[0..up_to_range_len], bytes[0..up_to_range_len]);
            @memcpy(new_bytes[up_to_range_len..(up_to_range_len + to_insert_len)], to_insert_bytes);
            @memcpy(new_bytes[(up_to_range_len + to_insert_len)..], bytes[(byte_end + 1)..]);

            return new_str;
        } else {
            // Figure out how long the new string needs to be.
            const up_to_range_len = byte_start;
            // Tcl ranges are inclusive, so `- 1` is needed.
            const after_range_len = bytes.len - byte_end - 1;

            const new_str = newStringToFill(Heap.getHeap(str), up_to_range_len + after_range_len);
            const new_bytes = Heap.getStringMut(new_str);

            @memcpy(new_bytes[0..up_to_range_len], bytes[0..up_to_range_len]);
            @memcpy(new_bytes[up_to_range_len..], bytes[(byte_end + 1)..]);

            return new_str;
        }
    } else {
        // Invalid range, so we'll just pass through the string.
        return try newStringWithCodepointLen(Heap.getHeap(str), bytes, codepoint_len);
    }
}

pub fn stringCaseConversion(str: Handle, mode: enum { upper, lower, title }) !Handle {
    const bytes = try Heap.getString(str);

    if (options.use_utf8) {
        // Go through once to calculate the length
        var new_len: usize = 0;
        var iter = stringutil.Iterator.init(bytes);
        var is_first_char = true;
        while (iter.next()) |cp| {
            var converted: u21 = undefined;
            switch (mode) {
                .upper => converted = stringutil.toUpper(cp),
                .lower => converted = stringutil.toLower(cp),
                .title => {
                    if (is_first_char) {
                        converted = stringutil.toTitle(cp);
                    } else {
                        converted = stringutil.toLower(cp);
                    }
                },
            }
            new_len += std.unicode.utf8ByteSequenceLength(converted);
            is_first_char = false;
        }

        const new_str = try newStringToFill(Heap.getHeap(str), new_len);
        const new_bytes = try Heap.getStringMut(new_str);

        // Now go through and write all the bytes
        iter = stringutil.Iterator.init(bytes);
        var written: usize = 0;
        is_first_char = true;
        while (iter.next()) |cp| {
            var converted: u21 = undefined;
            switch (mode) {
                .upper => converted = stringutil.toUpper(cp),
                .lower => converted = stringutil.toLower(cp),
                .title => {
                    if (is_first_char) {
                        converted = stringutil.toTitle(cp);
                    } else {
                        converted = stringutil.toLower(cp);
                    }
                },
            }
            written += std.unicode.utf8Encode(converted, new_bytes[written..]) catch unreachable;

            is_first_char = false;
        }
    } else {
        const new_len = bytes.len;
        const new_str = try newStringToFill(Heap.getHeap(str), new_len);
        const new_bytes = try Heap.getStringMut(new_str);

        for (bytes, new_bytes) |old_char, *new_char| {
            if (mode == .upper) {
                new_char.* = stringutil.toUpper(old_char);
            } else {
                new_char.* = stringutil.toLower(old_char);
            }
        }

        return new_str;
    }
}

/// Creates a new string if there was anything to trim.
pub fn stringTrimLeft(str: Handle, trim_chars: Handle) !Handle {
    const bytes = try Heap.getString(str);
    const trim_chars_bytes = try Heap.getString(trim_chars);

    const start = stringutil.trimLeft(bytes, trim_chars_bytes);

    if (start == 0) {
        return str;
    } else {
        return try newString(Heap.getHeap(str), bytes[start..]);
    }
}

/// Creates a new string if there was anything to trim.
pub fn stringTrimRight(str: Handle, trim_chars: Handle) !Handle {
    const bytes = try Heap.getString(str);
    const trim_chars_bytes = try Heap.getString(trim_chars);

    const end = stringutil.trimRight(bytes, trim_chars_bytes);

    if (end == bytes.len) {
        return str;
    } else {
        return try newString(Heap.getHeap(str), bytes[0..end]);
    }
}

/// Creates a new string if there was anything to trim.
pub fn stringTrim(str: Handle, trim_chars: Handle) !Handle {
    const bytes = try Heap.getString(str);
    const trim_chars_bytes = try Heap.getString(trim_chars);

    const start = stringutil.trimLeft(bytes, trim_chars_bytes);
    const end = stringutil.trimRight(bytes, trim_chars_bytes);

    if (start == 0 and end == bytes.len) {
        return str;
    } else {
        return try newString(Heap.getHeap(str), bytes[start..end]);
    }
}

/// Runs a string check based on requested class.
pub fn stringIs(str: *Handle, class_to_check: *Handle, strict: bool) !bool {
    const Classes = enum {
        integer,
        alpha,
        alnum,
        ascii,
        digit,
        double,
        lower,
        upper,
        space,
        xdigit,
        control,
        print,
        graph,
        punct,
        boolean,
    };
    const Mapping = std.StaticStringMap(Classes).initComptime(.{
        .{ "integer", .integer },
        .{ "alpha", .alpha },
        .{ "alnum", .alnum },
        .{ "ascii", .ascii },
        .{ "digit", .digit },
        .{ "double", .double },
        .{ "lower", .lower },
        .{ "upper", .upper },
        .{ "space", .space },
        .{ "xdigit", .xdigit },
        .{ "control", .control },
        .{ "print", .print },
        .{ "graph", .graph },
        .{ "punct", .punct },
        .{ "boolean", .boolean },
    });

    const class_bytes = try Heap.getString(class_to_check);
    const class = Mapping.get(class_bytes) orelse return error.BadEnumVariant;

    const bytes = try Heap.getString(*str);
    if (bytes.length == 0) {
        return !strict;
    }

    switch (class) {
        .integer => {
            std.fmt.parseInt(i64, bytes, 0) catch return false;
            return true;
        },
        .double => {
            std.fmt.parseFloat(f64, bytes) catch return false;
            return true;
        },
        .boolean => {
            getBoolean(str) catch return false;
            return true;
        },
        .alpha => return stringutil.checkAllAscii(bytes, std.ascii.isAlphabetic),
        .alnum => return stringutil.checkAllAscii(bytes, std.ascii.isAlphanumeric),
        .ascii => return stringutil.checkAllAscii(bytes, std.ascii.isAscii),
        .digit => return stringutil.checkAllAscii(bytes, std.ascii.isDigit),
        .lower => return stringutil.checkAllAscii(bytes, std.ascii.isLower),
        .upper => return stringutil.checkAllAscii(bytes, std.ascii.isUpper),
        .space => return stringutil.checkAllAscii(bytes, std.ascii.isWhitespace),
        .xdigit => return stringutil.checkAllAscii(bytes, stringutil.isHexDigit),
        .control => return stringutil.checkAllAscii(bytes, std.ascii.isControl),
        .print => return stringutil.checkAllAscii(bytes, std.ascii.isPrint),
        .graph => return stringutil.checkAllAscii(bytes, stringutil.isGraph),
        .punct => return stringutil.checkAllAscii(bytes, stringutil.isPunct),
    }
}

pub fn shimmerToBoolean(obj: Handle) !void {
    assert(Heap.canShimmer(obj));

    const Mapping = std.StaticStringMap(bool).initComptime(.{
        .{ "1", true },  .{ "true", true },   .{ "yes", true }, .{ "on", true },
        .{ "0", false }, .{ "false", false }, .{ "no", false }, .{ "off", false },
    });

    const bytes = try Heap.getString(obj);
    const new_value = Mapping.get(bytes) catch return error.BadBoolean;

    const ref = Heap.peek(obj);
    ref.tag = .bool;
    ref.body.bool = new_value;
}

pub fn getBoolean(obj: *Handle) !bool {
    if (Heap.peek(*obj).tag != .bool) {
        if (!Heap.canShimmer(obj)) {
            obj.* = Heap.getHeap(*obj).duplicate(obj);
        }

        try shimmerToBoolean(obj);
    }

    return Heap.peek(*obj).body.bool;
}
