const std = @import("std");

pub fn main() void {
    const str = "hello world";
    var iter = std.unicode.Utf8View.initUnchecked(str).iterator();

    std.debug.print("first item: {?u}\n", .{iter.nextCodepoint()});
    std.debug.print("second item: {?u}\n", .{iter.nextCodepoint()});
    std.debug.print("peek 0: {s}\n", .{iter.peek(0)});
    std.debug.print("peek 1: {s}\n", .{iter.peek(1)});
}
