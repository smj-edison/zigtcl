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

pub fn getUtf8Length(handle: Handle) !usize {
    try shimmerToString(handle);

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

/// Copies provided string.
pub fn newStringUtf8(heap: *Heap, bytes: [:0]const u8, utf8_length: usize) !Handle {
    const handle = try heap.createObject();
    Heap.setString(handle, bytes);
    shimmerToString(handle);

    const obj = Heap.peek(handle);
    switch (Heap.getStringDetails(handle)) {
        .long => |long_str| {
            long_str.utf8_length = utf8_length;
        },
        .normal => {
            obj.body.string.utf8_length = utf8_length;
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

/// [start, end)
pub const Range = struct {
    start: usize,
    end: usize,
};

pub fn constrainRange(list_len: usize, range: Range) Range {
    var new_range = range;

    // Make sure indexes are within the list.
    if (new_range.start >= list_len) {
        return .{
            .start = 0,
            .end = 0,
        };
    }
    if (new_range.end > list_len) {
        new_range.end = list_len;
    }

    if (new_range.start > new_range.end) {
        new_range.start = new_range.end;
    }

    return new_range;
}

pub fn getIndex(handle: Handle) !Heap.ListIndex {
    const obj = Heap.peek(handle);

    // Fast case: if it's an integer or float, we can quickly cast it
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

    if (obj.tag != .index) try shimmerToIndex(handle);

    return obj.body.index;
}

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
