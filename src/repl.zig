const std = @import("std");
//const uucode = @import("uucode");
const jim = @import("jim.c");

pub fn main() void {
    var cp: u21 = undefined;

    cp = 0x03C2;
    std.debug.print("hello world!", .{});
    //std.debug.print("Lower: {u}, upper: {u}.", .{ cp, uucode.get(.simple_uppercase_mapping, cp) });
}
