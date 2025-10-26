const std = @import("std");

const Handle = packed struct {
    index: u32,
    heap: u30,
    /// Whether this object can be ref counted (else it needs to be cloned)
    ref_counted: bool,
    _padding: u1 = 0,
};
const Object = packed struct {
    head: u64,
    body: u64,
};
const ObjectList = std.MultiArrayList(packed struct { object: Object });
const Heap = struct {
    objects: ObjectList,
    object_count: usize,
    heap_id: u30,

    pub fn createObject(self: *Heap, gpa: std.mem.Allocator) !Handle {
        const obj_id = self.object_count;
        self.object_count += 1;
        try self.objects.resize(gpa, self.object_count);

        self.objects.items(.object)[obj_id].head = 10;
        self.objects.items(.object)[obj_id].body = 10;
        return self.normalHandle(@intCast(obj_id));
    }

    pub fn normalHandle(self: *Heap, index: u32) Handle {
        return .{
            .heap = self.heap_id,
            .index = index,
            .ref_counted = true,
        };
    }
};
var heaps: [128]Heap = undefined;
var heap_id: usize = 0;

fn createHeap() *Heap {
    heap_id += 1;
    heaps[heap_id] = .{
        .objects = .{},
        .object_count = 0,
        .heap_id = @intCast(heap_id),
    };
    return &heaps[heap_id];
}

pub fn peek(handle: Handle) *Object {
    return &heaps[handle.heap].objects.items(.object)[handle.index];
}

test {
    // const page_size = std.heap.pageSize();
    // const res = std.heap.PageAllocator.map((1 << 32), .fromByteUnits(64));
    const ta = std.testing.allocator;

    const heap = createHeap();
    const obj = try heap.createObject(ta);
    const peeked = peek(obj);
    std.log.warn("Object: {}", .{peeked});
}
