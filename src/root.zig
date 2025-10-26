const std = @import("std");
const zigtcl = @import("zigtcl.zig");
const Parser = @import("parser.zig").Parser;
const string_utils = @import("string_utils.zig");

pub fn main() !void {
    var alloc = std.heap.page_allocator;

    const to_escape = "\\x41";
    var to_write = alloc.alloc(u8, to_escape.len) catch @panic("");
    defer alloc.free(to_write);

    const len = string_utils.removeEscaping(to_escape, to_write);
    std.debug.print("Result: {s}", .{to_write[0..len]});
}

test {
    // @import("std").testing.refAllDecls(@This());
    _ = @import("string_utils.zig");
    _ = @import("parser.zig");
    _ = @import("heap.zig");
}
