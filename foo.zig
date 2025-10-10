const std = @import("std");

pub fn main() !void {
    const str = "+0b10";

    const res = try std.fmt.parseInt(i64, str, 0);

    std.debug.print("{}\n", .{res});
}
