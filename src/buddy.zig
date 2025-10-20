//! Simple buddy allocator for any collection type.
//!
//! Based on https://www.kernel.org/doc/gorman/html/understand/understand009.html

const std = @import("std");
const math = std.math;
const assert = std.debug.assert;

const Config = struct {};

pub fn metadata_backing_size(order: u6) usize {
    // Explanation:
    // `@as(usize, 1) << (order - 1)`: This is the number of order 0 blocks.
    // For example, if you had order 4, you'd have:
    //  * order 3 = 1 block
    //  * order 2 = 2 blocks
    //  * order 1 = 4 blocks
    //  * order 0 = 8 blocks (the one in question)
    //
    // `* 2`: all the blocks of order 1 or higher fit within the size of the
    // order 0 blocks
    // `* 2`: two bits needed to represent left and right half of buddy
    // `/ @sizeOf(usize) * 8`: we use one bit to track each block. We use words
    // as the backing, so this returns the number of words needed to track
    // all the blocks of all the orders.
    return (@as(usize, 1) << (order - 1)) * 2 * 2 / (@sizeOf(usize) * 8);
}

/// `metadata_backing`'s size can be determined with `metadata_backing_size`.
pub fn BuddyUnmanaged(max_order: u6, config: Config) type {
    const metadata_word_size = metadata_backing_size(max_order);

    const MetadataBitSet = std.bit_set.ArrayBitSet(usize, metadata_word_size);

    return struct {
        metadata: MetadataBitSet,

        const Self = @This();

        pub fn init(metadata_backing: []usize) Self {
            assert(metadata_backing.len == metadata_word_size);

            @memset(metadata_backing, 0);
        }

        pub fn alloc(order: u6) error.OutOfMemory!usize {}

        fn alloc_impl() error.OutOfMemory!usize {}

        pub fn free(index: usize, order: u6) void {}

        const max_usize = @as(usize, math.maxInt(usize));
        fn order_bit_index(order: u6) usize {
            // Explanation:
            // The high-level mechanism of this bit trickery is sequentially setting bits,
            // in highest to lowest order. For example, say our max order is 4, and the
            // passed in order is one of the following:
            // order 0 = 0b0000
            // order 1 = 0b1000
            // order 2 = 0b1100
            // order 3 = 0b1110
            // We do this by starting with all bits set (max_usize). We then shift out
            // `max_order - order` bits, so when order is 0, all bits are shifted out of
            // the window. The window is then applied with a bitwise and.
            const pair_index = (max_usize << (max_order - order)) & ((@as(usize, 1) << max_order) - 1);
            // * 2 to account for two bits per pair
            return pair_index * 2;
        }
    };
}
