//! Common objects and their functions.
const std = @import("std");
const options = @import("options");
const stringutil = @import("./string_utils.zig");

const heap = @import("heap.zig");
const Handle = heap.Handle;

pub fn shimmerToString(handle: Handle) !void {
    const str = try heap.getString(handle); // Generate string representation
    heap.invalidateBody(handle);

    const obj = heap.peek(handle);
    if (str.len <= 7) {
        // Tiny string optimization
        var tiny_str: [8]u8 = 0 ** 8;
        const tiny_str_len = str.len;
        for (0..str.len) |i| tiny_str[i] = str[i];

        heap.invalidateString(handle);

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

    const obj = heap.peek(handle);
    const bytes = try heap.getString(handle);

    if (obj.tag == .string) {
        // See if we already calculated the utf8 length
        if (obj.str.is_ptr) {
            // LongString stores the utf8 length in the string body
            const long_string = heap.LongString.fromInt(obj.str.u.ptr);
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
pub fn newString(heap_id: heap.HeapId, bytes: [:0]const u8) !Handle {
    const str = try heap.heaps[heap_id].createObject();
    heap.setString(str, bytes);
    shimmerToString(str);
    return str;
}

/// Copies provided string.
pub fn newStringUtf8(heap_id: heap.HeapId, bytes: [:0]const u8, utf8_length: usize) !Handle {
    const str = try heap.heaps[heap_id].createObject();
    heap.setString(str, bytes);
    shimmerToString(str);

    // if ()

    return str;
}
