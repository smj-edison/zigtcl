const std = @import("std");

pub fn main() !void {
    const result: ?u32 = blk: {
        while (@rem(std.time.nanoTimestamp(), 2) == 0) {
            break :blk @as(u32, 10);
        }
        break :blk null;
    };

    std.debug.print("Value: {?}", .{result});
}
