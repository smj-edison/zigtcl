const std = @import("std");

pub fn main() !void {
    var x: u32 = 0;
    while (x < 10) : (break) {
        std.debug.print("x: {}\n", .{x});
        x += 1;
        continue;
    }
}
