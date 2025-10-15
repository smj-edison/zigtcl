const std = @import("std");

pub fn main() !void {
    var x: u32 = 0;
    while (x < 40) : (x += 2) {
        std.debug.print("Value: {}\n", .{x});
        if (@rem(x, 5) == 0) {
            x += 1;
            continue;
        }
    }
}
