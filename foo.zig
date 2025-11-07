const std = @import("std");

test {
    const ta = std.testing.allocator;
    _ = try ta.allocSentinel(u8, 7, 0);
}
