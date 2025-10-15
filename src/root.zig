const std = @import("std");
const zigtcl = @import("zigtcl.zig");
const Parser = @import("tokenizer.zig").Parser;
const string_utils = @import("string_utils.zig");

pub fn main() !void {
    var tokenizer = Parser.init(
        \\puts "hello world!"
    );
    _ = try tokenizer.next();
}

test {
    // @import("std").testing.refAllDecls(@This());
    _ = @import("string_utils.zig");
    _ = @import("tokenizer.zig");
}
