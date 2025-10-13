const std = @import("std");

pub fn main() !void {
    var x: u32 = 0;
    while (x < 10) {
        std.debug.print("x: {}\n", .{x});
        x += 1;

        const char = '(';

        switch (char) {
            '(' => {
                std.debug.print("first", .{});
            },
            '(', ')' => {
                std.debug.print("second", .{});
            },
        }
    }
}
