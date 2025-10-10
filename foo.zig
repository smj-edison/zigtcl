const std = @import("std");

pub fn main() void {
    const str = "hello world";
    var iter = std.unicode.Utf8View.initUnchecked(str).iterator();

    std.debug.print("first item: {?u}\n", .{iter.nextCodepoint()});
}
