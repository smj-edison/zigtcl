//! Simple buddy allocator for any collection type.
//!
//! Based on https://www.kernel.org/doc/gorman/html/understand/understand009.html

const std = @import("std");
const math = std.math;
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const FreeList = std.ArrayListUnmanaged(usize);

/// Dependant on parent allocator to resize the internal free lists
pub fn BuddyUnmanaged(max_order: comptime_int) type {
    return struct {
        // TODO: make this one data structure
        free_lists: [max_order]FreeList,

        const Self = @This();

        pub fn init(allocator: Allocator, initial_capacity: usize) error{OutOfMemory}!Self {
            var new_alloc: Self = .{
                .free_lists = undefined,
            };

            for (0..max_order) |i| {
                new_alloc.free_lists[i] = try FreeList.initCapacity(allocator, initial_capacity);
            }

            try new_alloc.free_lists[max_order - 1].append(allocator, 0);

            return new_alloc;
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            for (0..max_order) |i| {
                self.free_lists[i].deinit(allocator);
            }
        }

        pub fn alloc(self: *Self, allocator: Allocator, requested_order: u6) error{OutOfMemory}!usize {
            // look for an open block
            var open_index: usize = undefined;
            var open_order = requested_order;
            while (open_order < max_order) : (open_order += 1) {
                if (self.free_lists[open_order].pop()) |open| {
                    open_index = open;
                    break;
                }
            } else return error.OutOfMemory;

            // split blocks (if needed).
            while (open_order > requested_order) : (open_order -= 1) {
                try self.free_lists[open_order - 1].append(allocator, open_index + get_order_size(open_order - 1));
                // Lower half is implicitly passed along `open_index`, since
                // the lower block index stays the same as it descends
            }

            return open_index;
        }

        pub fn free(self: *Self, allocator: Allocator, index: usize, order: u6) error{OutOfMemory}!void {
            // TODO: add safety check that the allocation exists before freeing it

            var order_being_merged = order;
            var block_being_merged = index;

            // Why `< max_order - 1`? Because the top order has no sibling to merge with.
            while (order_being_merged < max_order - 1) : (order_being_merged += 1) {
                const sibling = sibling_of(block_being_merged, get_order_size(order_being_merged));

                std.debug.print(
                    "Order: {}, block: {}, sibling: {}\n",
                    .{ order_being_merged, block_being_merged, sibling },
                );

                var index_in_free_list: usize = undefined;
                for (self.free_lists[order_being_merged].items, 0..) |block, i| {
                    if (block == sibling) {
                        index_in_free_list = i;
                        break;
                    }
                } else {
                    // Couldn't find sibling, so we'll put this one on the
                    // free list.
                    try self.free_lists[order].append(allocator, index);
                    return;
                }

                // We've found the sibling, so now we can merge.

                // Remove sibling from free list
                _ = self.free_lists[order_being_merged].swapRemove(index_in_free_list);

                block_being_merged = @min(block_being_merged, sibling);
                try self.free_lists[order_being_merged + 1].append(allocator, block_being_merged);
            }
        }

        fn sibling_of(index: usize, order_size: usize) usize {
            const mask = (order_size * 2) - 1;

            if (index & mask == 0) {
                return index + order_size;
            } else {
                return index - order_size;
            }
        }

        fn get_order_size(order: u6) usize {
            return @as(usize, 1) << order;
        }
    };
}

const expectEqual = std.testing.expectEqual;
const expectError = std.testing.expectError;

const TestAlloc = BuddyUnmanaged(5);
fn print_buddy_state(beginning: []const u8, alloc: TestAlloc) void {
    std.debug.print("{s}", .{beginning});
    for (0..alloc.free_lists.len) |order| {
        std.debug.print("Order: {} ({any}), ", .{ order, alloc.free_lists[order].items });
    }
    std.debug.print("\n", .{});
}

test "Buddy allocator" {
    const ta = std.testing.allocator;

    var alloc = try TestAlloc.init(ta, 16);
    defer alloc.deinit(ta);

    print_buddy_state("0. ", alloc);
    try expectEqual(0, try alloc.alloc(ta, 0));
    print_buddy_state("1. ", alloc);
    try expectEqual(1, try alloc.alloc(ta, 0));
    print_buddy_state("2. ", alloc);
    try expectEqual(2, try alloc.alloc(ta, 0));
    print_buddy_state("3. ", alloc);

    try expectEqual(4, try alloc.alloc(ta, 1));
    print_buddy_state("4. ", alloc);
    try expectEqual(3, try alloc.alloc(ta, 0));
    print_buddy_state("5. ", alloc);

    try expectEqual(8, try alloc.alloc(ta, 3));

    //
    print_buddy_state("\n6. ", alloc);
    try alloc.free(ta, 0, 0);
    print_buddy_state("7. ", alloc);
    try alloc.free(ta, 1, 0);
    print_buddy_state("8. ", alloc);
    try alloc.free(ta, 2, 0);
    print_buddy_state("9. ", alloc);

    try alloc.free(ta, 4, 1);
    print_buddy_state("10. ", alloc);
    try alloc.free(ta, 3, 0);
    print_buddy_state("11. ", alloc);

    try alloc.free(ta, 8, 3);
    print_buddy_state("12. ", alloc);

    try expectEqual(0, try alloc.alloc(ta, 3));
}
