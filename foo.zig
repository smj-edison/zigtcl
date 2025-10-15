const std = @import("std");

const errors = error{ FooBar, BazQux };
pub fn main() !void {
    std.debug.print("Type: {s}", .{@typeName(@TypeOf(error.FooBar))});
}
