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
    const total_block_count = 1 << max_order;
    const AllocTracking = std.bit_set.ArrayBitSet(usize, total_block_count / (@sizeOf(usize) * 8));

    return struct {
        // TODO: make this one data structure
        next_free: [max_order]FreeList,
        alloc_tracking: AllocTracking,

        const Self = @This();

        fn init(allocator: Allocator, initial_capacity: usize) Self {
            var new_alloc: Self = .{
                .next_free = undefined,
            };

            for (0..max_order) |i| {
                new_alloc.next_free[i] = FreeList.initCapacity(allocator, initial_capacity);
            }

            new_alloc.next_free[max_order - 1] = 0;
        }

        pub fn alloc(self: Self, allocator: Allocator, requested_order: u6) error.OutOfMemory!usize {
            // look for an open block
            var open_index = undefined;
            var open_order = requested_order;
            while (open_order < max_order) : (open_order += 1) {
                if (self.next_free[open_order].pop()) |open| {
                    open_index = open;
                    break;
                }
            } else return error.OutOfMemory;

            // split blocks (if needed).
            while (open_order > requested_order) : (open_order -= 1) {
                self.next_free[open_order - 1].append(allocator, open_index + get_order_size(open_order - 1));
                // Lower half is implicitly passed along `open_index`, since
                // the lower block index stays the same as it descends
            }

            return open_index;
        }

        pub fn free(self: Self, allocator: Allocator, index: usize, order: u6) void {
            const bit_index = alloc_bit_index(index, order);

            // Ensure this allocation even existed in the first place.
            if (!self.alloc_tracking.isSet(bit_index)) {
                @panic("Double free");
            }

            // Combine with sibling, if sibling exists and is free.

            var order_being_merged = order;
            var block_being_merged = index;

            // Can't merge top order with sibling, as it has no sibling, hence `max_order - 1`
            while (order_being_merged < max_order - 1) : (order_being_merged += 1) {
                const sibling = sibling_of(block_being_merged);

                var index_in_free_list = undefined;
                for (self.next_free[order_being_merged].items, 0..) |block, i| {
                    if (block == sibling) break;
                    index_in_free_list = i;
                } else return; // Couldn't find sibling.

                // We've found the sibling, so now we can merge.

                // Remove sibling from free list
                self.next_free[order_being_merged].swapRemove(index_in_free_list);

                block_being_merged = @min(block_being_merged, sibling);
                self.next_free[order_being_merged + 1].append(allocator, block_being_merged);
            } else {
                self.next_free[order].append(allocator, index);
            }
        }

        const max_order_offset = (@as(usize, 1) << (max_order - 1)) - 1;
        fn alloc_bit_index(index: usize, order: u6) usize {
            return (index >> order) + (max_order_offset >> order);
        }

        fn sibling_of(index: usize, order_size: u6) usize {
            const mask = (order_size * 2) - 1;

            if (index & mask == 0) {
                return index + order_size;
            } else {
                return index - order_size;
            }
        }

        fn get_order_size(order: u6) usize {
            return @as(usize, 1) << (order + 1);
        }
    };
}
