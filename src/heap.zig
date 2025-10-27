const std = @import("std");
const math = std.math;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const string_utils = @import("string_utils.zig");
const memutil = @import("memutil.zig");

// These numbers are final, and can be depended on to be their current values
const null_string = 0;
const empty_string = 1;

const global_heap_id = 0;
// --- //

pub const HeapSettings = struct {
    /// threading only works on 64-bit machines, because
    /// the object heads are atomically swapped.
    threading: bool = true,
    use_vmem: bool = true,
    /// Maximum of `1 << heap_order` items.
    object_heap_order: u6 = 24,
    /// Maximum of `1 << heap_order` bytes for all strings.
    string_heap_order: u6 = 28,
    /// Maximum number of custom types.
    max_custom_types: usize = 65536,
    /// Maximum number of heaps (not necessarily initialized).
    max_heaps: usize = 128,
    /// Maximum number of custom type instances.
    max_custom_type_instances: u32 = 65536,
};
const cfg: HeapSettings = .{};

const Heap = @This();

const object_heap_max_count: usize = @as(usize, 1) << cfg.object_heap_order;
const object_heap_max_bytes: usize = ObjectList.capacityInBytes(object_heap_max_count);
const string_heap_max_bytes: usize = @as(usize, 1) << cfg.string_heap_order;

// Heap fields
gpa: Allocator,
heap_id: HeapId,

/// Used to lock object_tracking and string_tracking
tracking_mutex: Mutex = .{},
object_tracking: ObjectTracker,
objects: ObjectList,
string_tracking: StringTracker,
strings: StringList,
type_instances: CustomTypeInstanceList,

const Object = packed struct {
    pub const StrOrPtr = packed struct {
        u: packed union {
            str: packed struct {
                index: u32,
                length: u26,
            },
            /// Be sure to >> 6 before setting, and << 6 when reading. Must be non-null.
            ptr: u58,
        },
        is_ptr: bool,
    };

    str: StrOrPtr,
    tag: Tag,
    body: Body,

    fn hasNullString(self: Object) bool {
        if (self.str.is_ptr) {
            return false;
        } else {
            // Must check length too, as tiny strings use a null index but non-zero length
            return self.str.u.str.index == 0 and self.str.u.str.length == 0;
        }
    }
};

comptime {
    assert(@sizeOf(Object) == 16);
}

pub const Tag = enum(u5) {
    none,
    index,
    return_code,
    number,
    float,
    /// `.tiny_string` _must_ have at least one byte (e.g. not null and not empty)
    tiny_string,
    string,
    list,
    reference,
    custom_type,
};

pub const Body = packed union {
    /// Array index
    index: u32,
    return_code: bool,
    number: i64,
    float: f64,
    string: packed struct {
        /// If = utf8_length > maxInt(u32), it means the length has not been determined
        utf8_length: u33,
    },
    /// String of up to length 8
    tiny_string: packed struct {
        /// Must be cast to [7:0]u8
        bytes: u64,
    },
    list: packed struct {
        start: u32,
        length: u32,
    },
    reference: Handle,
    custom_type: packed struct {
        type_id: u32,
        index: u32,
    },
};

comptime {
    assert(@sizeOf(Body) == 8);
}

pub const CustomType = struct {
    name: []u8, // Type name
    invalidate_body: *const fn (heap: *Heap, obj: *Object) void,
    duplicate: *const fn (heap: *Heap, src: *const Object, dest: *Object) void,
    get_string: *const fn (heap: *Heap, obj: *const Object) Allocator.Error![:0]u8,
    make_immutable: *const fn (heap: *Heap, obj: *Object) void,
};

pub const Handle = packed struct {
    index: u32,
    heap: u30,
    /// Whether this object can be ref counted (else it needs to be cloned)
    ref_counted: bool,
    _padding: u1 = 0,
};

const HeapError = error{WrongHeap};
pub const HeapId = u30;

const Mutex = if (cfg.threading) std.Thread.Mutex else DummyMutex;

const ObjectTracker = memutil.BuddyUnmanaged(cfg.object_heap_order);
const ObjectList = std.MultiArrayList(ObjectAndMetadata);
const StringTracker = memutil.BuddyUnmanaged(cfg.string_heap_order);
const StringList = std.ArrayList(u8);
const CustomTypeInstance = *anyopaque;
const CustomTypeInstanceList = std.ArrayList(CustomTypeInstance);

const ObjectAndMetadata = struct {
    object: Object,
    ref_count: u32,
    metadata: packed struct {
        order: u6,
        /// Whether this object is the front of the allocation
        /// (if not, this index will not be freed, as it's
        /// managed by another object)
        is_alloc_head: bool,
        /// Whether this object is shared across threads
        cross_thread: bool,
    },
};

fn heapAlloc(self: *Heap) Allocator {
    if (cfg.use_vmem or cfg.threading) {
        return memutil.null_allocator;
    } else {
        return self.gpa;
    }
}

pub fn init(gpa: Allocator, heap_id: HeapId) !Heap {
    // Init objects
    var object_tracking = try ObjectTracker.init(gpa, cfg.object_heap_order);
    errdefer object_tracking.deinit(gpa);

    var objects: ObjectList = .{};
    if (cfg.use_vmem) {
        objects.bytes = (try memutil.vmemMap(object_heap_max_bytes)).ptr;
        objects.capacity = object_heap_max_count;
    } else if (cfg.threading) {
        // if multithreading, we can't have objects moving around. We better allocate
        // everything up front.
        try objects.ensureTotalCapacity(gpa, object_heap_max_count);
    } else {
        try objects.ensureTotalCapacity(gpa, 32);
    }
    errdefer {
        if (cfg.use_vmem) {
            memutil.vmemUnmap(@alignCast(objects.bytes[0..objects.capacity]));
        } else {
            objects.deinit(gpa);
        }
    }

    // Init strings
    var string_tracking = try StringTracker.init(gpa, 32);
    errdefer string_tracking.deinit(gpa);

    var strings: StringList = .{};
    if (cfg.use_vmem) {
        strings.items = try memutil.vmemMap(string_heap_max_bytes);
    } else if (cfg.threading) {
        // if multithreading, we can't have strings moving around. We better allocate
        // everything up front.
        try strings.ensureTotalCapacity(gpa, string_heap_max_bytes);
    } else {
        try strings.ensureTotalCapacity(gpa, 32);
    }
    errdefer if (cfg.use_vmem) memutil.vmemUnmap(strings.items) else strings.deinit(gpa);

    // Init type instances
    var type_instances: CustomTypeInstanceList = .{};
    if (cfg.use_vmem) {
        type_instances.items = try memutil.vmemMapItems(CustomTypeInstance, cfg.max_custom_type_instances);
    } else if (cfg.threading) {
        // if multithreading, we can't have strings moving around. We better allocate
        // everything up front.
        try type_instances.ensureTotalCapacity(gpa, cfg.max_custom_type_instances);
    } else {
        try type_instances.ensureTotalCapacity(gpa, 32);
    }
    errdefer if (cfg.use_vmem) {
        memutil.vmemUnmapItems(CustomTypeInstance, type_instances.items);
    } else {
        type_instances.deinit(gpa);
    };

    // Create heap
    var heap = Heap{
        .gpa = gpa,
        .heap_id = heap_id,
        .object_tracking = object_tracking,
        .objects = objects,
        .string_tracking = string_tracking,
        .strings = strings,
        .type_instances = type_instances,
    };

    // Specialty objects
    // null object is guaranteed to have index 0
    const null_object = try heap.createObject();
    assert(null_object.index == 0);

    // null string is guaranteed to have index 0
    const null_string_idx = try heap.string_tracking.alloc(gpa, 0);
    assert(null_string_idx == null_string);
    // empty string is guaranteed to have index 1
    const empty_string_idx = try heap.string_tracking.alloc(gpa, 0);
    assert(empty_string_idx == empty_string);

    return heap;
}

pub fn deinit(self: *Heap) void {
    if (cfg.use_vmem) {
        memutil.vmemUnmap(@alignCast(self.strings.items));
        memutil.vmemUnmap(@alignCast(self.objects.bytes[0..self.objects.capacity]));
        memutil.vmemUnmapItems(CustomTypeInstance, self.type_instances.items);
    } else {
        // Don't use self.heapAlloc() in this case, as that will error
        // with the null allocator
        self.strings.deinit(self.gpa);
        self.objects.deinit(self.gpa);
    }
    self.object_tracking.deinit(self.gpa);
    self.string_tracking.deinit(self.gpa);
}

pub fn createObject(self: *Heap) !Handle {
    const index = try self.createObjects(1);
    return .{
        .index = index,
        .heap = self.heap_id,
        .ref_counted = true,
    };
}

/// create_objects does not initialize objects, but does initialize
/// reference counts.
pub fn createObjects(self: *Heap, count: u32) !u32 {
    self.lockTracking();
    const order = memutil.getOrder(count);
    const index: u32 = @intCast(try self.object_tracking.alloc(self.gpa, order));
    const end = index + count;
    self.unlockTracking();

    // Make sure arrays have space for new objects
    if (self.objects.len < index + count) {
        try self.objects.resize(self.heapAlloc(), index + count);
    }

    // Initialize to empty object
    @memset(self.objects.items(.object)[index..end], .{
        .str = .{
            .u = .{ .str = .{ .index = 0, .length = 0 } },
            .is_ptr = false,
        },
        .tag = .none,
        .body = .{
            .number = 0,
        },
    });

    // Initialize ref counts
    @memset(self.objects.items(.ref_count)[index..end], 1);

    // Initialize metadata
    self.objects.items(.metadata)[index] = .{
        .order = order,
        .is_alloc_head = true,
        .cross_thread = false,
    };

    if (count > 1) @memset(
        self.objects.items(.metadata)[(index + 1)..end],
        .{
            .order = order,
            .is_alloc_head = false,
            .cross_thread = false,
        },
    );

    return index;
}

fn freeLocalObject(self: *Heap, index: u32) void {
    self.invalidateLocalString(index);
    self.invalidateLocalBody(index);

    const metadata = self.objects.get(index).metadata;
    if (metadata.is_alloc_head) {
        self.lockTracking();
        self.object_tracking.free(index, metadata.order);
        self.unlockTracking();
    }
}

pub fn invalidateString(handle: Handle) void {
    heaps[handle.index].invalidateLocalString(handle.index);
}

pub fn invalidateBody(handle: Handle) void {
    heaps[handle.index].invalidateLocalBody(handle.index);
}

fn invalidateLocalString(self: *Heap, index: u32) void {
    const obj: *Object = &self.objects.items(.object)[index];

    switch (self.getLocalStringDetails(index)) {
        .long => |long_str| {
            long_str.decrRefCount();
        },
        .normal => {
            self.freeString(obj.str.u.str.index, obj.str.u.str.length);
        },
        .null, .empty, .tiny => {},
    }

    // Be sure to mark as having no string
    obj.str.is_ptr = false;
    obj.str.u.str = .{
        .index = 0,
        .length = 0,
    };
}

fn invalidateLocalBody(self: *Heap, index: u32) void {
    const obj: *Object = &self.objects.items(.object)[index];

    switch (obj.tag) {
        .list => {
            const list = obj.body.list;

            for (0..list.length) |i| {
                self.freeLocalObject(@intCast(list.start + i));
            }
        },
        .custom_type => {
            const custom_type = obj.body.custom_type;
            const type_fns = custom_types[custom_type.type_id];

            type_fns.invalidate_body(self, obj);
        },
        .reference => {
            const target = obj.body.reference;
            self.release(target);
        },
        .string => {
            // How come string is a no-op? Because we could potentially
            // double-free when freeStringRep is called.
        },
        .tiny_string, .none, .index, .return_code, .number, .float => {},
    }
}

/// Allocates 1 + length, in order to make space for the null byte
fn createString(self: *Heap, length: u32) !u32 {
    const length_with_null = length + 1;
    self.lockTracking();
    defer self.unlockTracking();
    const new_string: u32 = @intCast(try self.string_tracking.allocCount(self.gpa, length_with_null));
    return new_string;
}

fn freeString(self: *Heap, index: u32, length: u32) void {
    const length_with_null = length + 1;
    self.lockTracking();
    self.string_tracking.freeCount(index, length_with_null);
    self.unlockTracking();
}

pub fn borrow(self: *Heap, handle: Handle) !Handle {
    // If the object isn't ref counted, then we'll need to clone it (i.e. a list item)
    if (!handle.ref_counted) {
        return try self.duplicate(handle);
    }

    // This object may have come from another heap
    const heap = &heaps[handle.heap];

    if (cfg.threading and heap.objects.get(handle.index).metadata.cross_thread) {
        _ = @atomicRmw(u32, &heap.objects.items(.ref_count)[handle.index], .Add, 1, .monotonic);
    } else {
        heap.objects.items(.ref_count)[handle.index] += 1;
    }

    return handle;
}

pub fn release(self: *Heap, handle: Handle) void {
    if (!handle.ref_counted) return;

    _ = self;

    // This object may have come from another heap
    var heap = &heaps[handle.heap];

    // If after_sub == 0, then this object will be freed
    var after_sub: u32 = undefined;
    if (cfg.threading and heap.objects.get(handle.index).metadata.cross_thread) {
        const before_sub = @atomicRmw(u32, &heap.objects.items(.ref_count)[handle.index], .Sub, 1, .release);
        after_sub = before_sub - 1;

        if (after_sub == 0) {
            _ = @atomicLoad(u32, &heap.objects.items(.ref_count)[handle.index], .acquire);
        }
    } else {
        heap.objects.items(.ref_count)[handle.index] -= 1;
        after_sub = heap.objects.get(handle.index).ref_count;
    }

    if (after_sub == 0) {
        heap.freeLocalObject(handle.index);
    }
}

fn duplicateObjString(self: *Heap, index: u32) !Object.StrOrPtr {
    switch (self.getLocalStringDetails(index)) {
        .long => |long_str| {
            long_str.incrRefCount();
            return .{
                .u = .{ .ptr = LongString.toInt(long_str) },
                .is_ptr = true,
            };
        },
        .normal => |bytes| {
            const new_string = try self.createString(bytes.len);
            @memcpy(self.strings.items[new_string..(new_string + bytes.length) :0], bytes);

            return .{
                .u = .{ .str = .{ .index = new_string, .length = bytes.length } },
                .is_ptr = false,
            };
        },
        .tiny, .null, .empty => {
            // Caller is responsible to copy the tiny string
            const obj = self.getLocalObject(index);
            return obj.str;
        },
    }
}

fn duplicateSingle(self: *Heap, index: u32) !Object {
    const src = self.getLocalObject(index);
    switch (src.tag) {
        .none, .index, .return_code, .number, .float, .string, .tiny_string => {
            return .{
                .str = try self.duplicateObjString(src),
                .tag = src.tag,
                .body = src.body,
            };
        },
        .reference => {
            const ref = src.body.reference;
            const new_handle = try self.duplicate(ref);
            return .{
                .str = .{
                    .u = .{ .str = .{ .index = 0, .length = 0 } },
                    .is_ptr = false,
                },
                .tag = .reference,
                .body = .{ .reference = new_handle },
            };
        },
        .custom_type => {
            const custom_type = src.body.custom_type;

            var new_object: Object = .{
                .str = try self.duplicateObjString(index),
                .tag = .custom_type,
                .body = .{
                    .custom_type = .{
                        .index = self.createCustomTypeInstance(),
                    },
                },
            };
            custom_types[custom_type.type_id].duplicate(self, src, &new_object);

            return new_object;
        },
        .list => {
            @panic("duplicateSingle called with multi item object");
        },
    }
}

pub fn duplicate(self: *Heap, handle: Handle) error{OutOfMemory}!Handle {
    const src = peek(handle);

    switch (src.tag) {
        .list => {
            const old_head = src;
            const old_body = old_head.body.list;
            const old_start = old_body.start;
            const old_end = old_body.start + old_body.length;
            const old_items = heaps[handle.heap].objects.items(.object)[old_start..old_end];

            const new_list_idx = try self.createObjects(1 + old_body.length);
            errdefer {
                // Iterate in reverse order to prevent freeing the head of the list first
                var i = new_list_idx + 1 + old_body.length;
                while (i > 0) {
                    i -= 1;
                    self.release(self.normalHandle(i));
                }
            }
            var new_head: *Object = &self.objects.items(.object)[new_list_idx];
            const new_start = new_list_idx + 1;
            const new_end = new_start + old_body.length;
            var new_items = self.objects.items(.object)[new_start..new_end];

            new_head.* = try self.duplicateObjString(old_head);
            new_head.tag = .list;
            new_head.body.list = .{
                .start = new_list_idx + 1,
                .length = old_body.length,
            };

            var i: usize = 0;
            while (i < old_body.length) : (i += 1) {
                new_items[i] = try self.duplicateSingle(&old_items[i]);
            }

            return self.normalHandle(new_list_idx);
        },
        else => {
            const new_object = try self.createObject();
            self.objects.items(.object)[new_object.index] = try self.duplicateSingle(src);
            return new_object;
        },
    }
}

pub fn normalHandle(self: *Heap, index: u32) Handle {
    return .{
        .heap = self.heap_id,
        .index = index,
        .ref_counted = true,
    };
}

pub fn peek(handle: Handle) *Object {
    return &heaps[handle.heap].getLocalObject(handle.index);
}

fn getLocalObject(self: *Heap, index: u32) *Object {
    return self.objects.items(.object)[index];
}

pub fn getString(handle: Handle) ![:0]const u8 {
    return try heaps[handle.heap].getLocalString(handle.index);
}

/// Copies provided string.
pub fn setString(handle: Handle, bytes: [:0]const u8) !void {
    const heap = heaps[handle.heap];
    const new_str = try heap.gpa.dupeZ(u8, bytes);
    errdefer heap.gpa.free(new_str);
    const took_ownership = try heap.setLocalString(handle.index, new_str);
    if (!took_ownership) heap.gpa.free(new_str);
}

/// Returns whether it took ownership of the bytes.
fn setLocalString(self: *Heap, index: usize, bytes: [:0]u8) !bool {
    var took_ownership = false;

    // Figure out the best way to represent the string (tiny string is not
    // an option as the body is already occupied with another type)
    var new_str_or_ptr: Object.StrOrPtr = undefined;
    if (bytes.len == 0) {
        new_str_or_ptr.u.str = .{
            .index = empty_string,
            .length = 0,
        };
        new_str_or_ptr.is_ptr = false;
    } else if (bytes.len < LongString.split_point) {
        const local_string = try self.createString(@intCast(bytes.len));
        @memcpy(
            self.strings.items[local_string..(local_string + bytes.len) :0],
            bytes,
        );

        new_str_or_ptr.u.str = .{
            .index = local_string,
            .length = @intCast(bytes.len),
        };
        new_str_or_ptr.is_ptr = false;
    } else {
        took_ownership = true;

        const new_string = &(try self.gpa.alignedAlloc(LongString, LongString.align_type, 1))[0];
        new_string.* = .{
            .string = bytes,
            .ref_count = 1,
            .utf8_length = null,
        };

        new_str_or_ptr.u.ptr = LongString.toInt(new_string);
        new_str_or_ptr.is_ptr = true;
    }

    const obj: *Object = &self.objects.items(.object)[index];
    if (cfg.threading and self.objects.get(index).metadata.cross_thread) {
        // Atomically swap only the first half of the object
        if (@sizeOf(Object) - @sizeOf(Body) != 8) @compileError("Object head must be exactly 8 bytes");
        if (@bitSizeOf(Object.StrOrPtr) != 59) @compileError("StrOrPtr must be exactly 59 bits wide");
        if (@bitOffsetOf(Object.StrOrPtr, "is_ptr") != 58) @compileError("Object.StrOrPtr.is_ptr must be in bit position 58");

        const str_all_mask: u64 = (1 << 59) - 1;
        const str_data_mask: u64 = (1 << 58) - 1;

        const object_head: *u64 = @ptrCast(obj);
        var old_obj = @atomicLoad(u64, object_head, .monotonic);

        while (true) {
            // Is the string pointer not null?
            if (old_obj & str_data_mask != 0) {
                // Somebody else must've won this, so we'll use their string
                if (new_str_or_ptr.is_ptr) {
                    took_ownership = false;
                    LongString.fromInt(new_str_or_ptr.u.ptr).freeUnchecked();
                } else {
                    const local_string = new_str_or_ptr.u.str;
                    if (local_string.index > 1) {
                        self.freeString(local_string.index, local_string.length);
                    }
                }

                break;
            }

            // Preserve tag from old_obj
            var new_obj = old_obj & ~str_all_mask;
            const new_obj_str: u59 = @bitCast(new_str_or_ptr);
            new_obj |= new_obj_str;

            const res: ?u64 = @cmpxchgWeak(u64, object_head, old_obj, new_obj, .release, .acquire);

            if (res) |winning_obj| {
                old_obj = winning_obj;
                continue;
            } else {
                // Successfully swapped
                break;
            }
        }
    } else {
        obj.str = new_str_or_ptr;
    }

    return took_ownership;
}

const empty_string_value = "";
/// This returns a temporary string. Whenever the object is modified, it
/// may become invalid.
fn getLocalString(self: *Heap, index: u32) error{OutOfMemory}![:0]const u8 {
    const obj: *Object = &self.objects.items(.object)[index];

    // Check if it already has a string representation
    if (obj.str.is_ptr and obj.str.u.ptr != 0) {
        return LongString.fromInt(obj.str.u.ptr).string;
    } else if (!obj.str.is_ptr) {
        const str = obj.str.u.str;

        if (obj.tag == .tiny_string) {
            const str_value: *[8]u8 = @ptrCast(&obj.body.tiny_string.bytes);
            return str_value[0..str.length :0];
        } else if (str.index == null_string) {
            // Null string, don't return so we keep going in the function
        } else if (str.index == empty_string) {
            return empty_string_value;
        } else {
            return self.strings.items[str.index..(str.index + str.length) :0];
        }
    }

    // No representation, so we better generate it
    var new_str: [:0]u8 = undefined;
    switch (obj.tag) {
        .index => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.index}, 0);
        },
        .return_code => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.return_code}, 0);
        },
        .number => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.number}, 0);
        },
        .float => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.float}, 0);
        },
        .list => {
            const list = obj.body.list;
            new_str = try getListString(self, list.start, list.length);
        },
        .custom_type => {
            const custom_type = obj.body.custom_type;
            new_str = try custom_types[custom_type.type_id].get_string(self, obj);
        },
        .reference => {
            return getString(obj.body.reference);
        },
        .string, .tiny_string, .none => {
            @panic("Tried to generate a string with no body");
        },
    }

    const took_ownership = try self.setLocalString(index, new_str);
    if (!took_ownership) self.gpa.free(new_str);

    // Rerun this function to figure out where the new string is
    return self.getLocalString(index);
}

fn getListString(self: *Heap, index: u32, length: u32) ![:0]u8 {
    var fallback = std.heap.stackFallback(64, self.gpa);
    var stack_alloc = fallback.get();
    var quoting_types = try stack_alloc.alloc(string_utils.QuotingType, length);
    defer stack_alloc.free(quoting_types);

    // Step 1: calculate the string length.
    var total_length: usize = 0;
    for (0..length) |i| {
        const element_string = try self.getLocalString(@intCast(index + i));
        quoting_types[i] = string_utils.calculateNeededQuotingType(element_string);
        if (i == 0 and quoting_types[i] == .bare and
            element_string.len > 0 and element_string[0] == '#')
        {
            // Make sure the first element has # escaped in braces
            quoting_types[i] = .brace;
        }
        total_length += string_utils.quoteSize(quoting_types[i], element_string.len);
        total_length += 1; // space between each element
    }

    // Step 2: actually create said string.
    var unfinished_str = try self.gpa.alloc(u8, total_length + 1);
    errdefer self.gpa.free(unfinished_str);
    var written: usize = 0;

    for (0..length) |i| {
        const element_string = try self.getLocalString(@intCast(index + i));
        written += string_utils.quoteString(
            quoting_types[i],
            element_string,
            unfinished_str[written..],
            i == 0,
        );

        // Add a space (except at the end of the list)
        if (i + 1 < length) {
            unfinished_str[written] = ' ';
            written += 1;
        }
    }

    // Slap a nul on the end
    unfinished_str[written] = 0x00;
    written += 1;

    // We actually need to realloc, because allocator.free needs the
    // original slice length (and we don't track the original slice
    // length, only the accessible length)
    const finished_str = try self.gpa.realloc(unfinished_str, written);
    return finished_str[0..(written - 1) :0];
}

const StringDetails = union(enum) {
    null: void,
    empty: void,
    tiny: [:0]const u8,
    normal: [:0]const u8,
    long: *LongString,
};

fn getLocalStringDetails(self: *Heap, index: u32) StringDetails {
    const obj = self.getLocalObject(index);

    // Tiny string optimization?
    if (obj.tag == .tiny_string) {
        // Tiny strings are guaranteed to have at least one byte,
        // so not null, and not empty.
        const as_bytes: *[7:0]u8 = @ptrCast(&obj.body.tiny_string.bytes);
        return .{
            .tiny = as_bytes[0..obj.str.u.str.length :0],
        };
    }

    // Normal string or long string
    if (obj.tag == .string) {
        if (obj.str.is_ptr) {
            // Convert to LongString ptr (guaranteed to be non-null)
            return .{
                .long = LongString.fromInt(obj.str.u.ptr),
            };
        } else {
            const str = obj.str.u.str;
            if (str.index == null_string) {
                return .null;
            } else if (str.index == empty_string) {
                return .empty;
            } else {
                return .{
                    .normal = &self.strings.items[str.index..(str.index + str.length)],
                };
            }
        }
    }
}

fn lockTracking(self: *Heap) void {
    if (self.heap_id == global_heap_id) self.tracking_mutex.lock();
}

fn unlockTracking(self: *Heap) void {
    if (self.heap_id == global_heap_id) self.tracking_mutex.unlock();
}

pub const LongString = struct {
    /// At what point should we switch to using a long string?
    /// Whenever the string length >= split_point
    pub const split_point = 100_000;
    pub const align_amt = 128;
    pub const align_type = std.mem.Alignment.fromByteUnits(align_amt);

    string: [:0]u8,
    utf8_length: ?u64,
    ref_count: usize,

    pub fn fromInt(int: u58) *align(align_amt) LongString {
        return @ptrFromInt(int << 6);
    }

    pub fn toInt(ptr: *align(align_amt) LongString) u58 {
        return @intCast(@intFromPtr(ptr) >> 6);
    }

    pub fn incrRefCount(self: *align(align_amt) LongString) void {
        if (cfg.threading) {
            _ = @atomicRmw(usize, &self.ref_count, .Add, 1, .monotonic);
        } else {
            self.ref_count += 1;
        }
    }

    pub fn decrRefCount(gpa: Allocator, self: *align(align_amt) LongString) void {
        if (cfg.threading) {
            _ = @atomicRmw(usize, &self.ref_count, .Sub, 1, .monotonic);
        } else {
            self.ref_count -= 1;
        }

        if (self.ref_count == 0) {
            self.freeUnchecked(gpa);
        }
    }

    pub fn freeUnchecked(self: *align(align_amt) LongString, gpa: Allocator) void {
        gpa.destroy(self);
    }
};

pub const CustomTypes = struct {
    elem: [cfg.max_custom_types]CustomType = undefined,
    next_open: usize = 0,

    pub fn getAvailableSlot(self: *CustomTypes) ?usize {
        var slot_index = undefined;
        if (cfg.threading) {
            slot_index = @atomicRmw(usize, &self.next_open, .Add, 1, .monotonic);
        } else {
            slot_index = self.next_open;
            self.next_open += 1;
        }

        if (slot_index < cfg.max_custom_types) {
            return slot_index;
        } else {
            return null;
        }
    }
};

// Heap instances //
pub var heaps: [cfg.max_heaps]Heap = undefined;
var next_open_heap: usize = 0;
pub var custom_types: [cfg.max_custom_types]CustomType = undefined;
var next_open_type: usize = 0;

pub fn createHeap(gpa: Allocator) !?*Heap {
    var slot_index: usize = undefined;
    if (cfg.threading) {
        slot_index = @atomicRmw(usize, &next_open_heap, .Add, 1, .monotonic);
    } else {
        slot_index = next_open_heap;
        next_open_heap += 1;
    }

    if (slot_index < cfg.max_heaps) {
        heaps[slot_index] = try init(gpa, @intCast(slot_index));
        return &heaps[slot_index];
    } else {
        return null;
    }
}

pub fn deinitAll() void {
    for (heaps[0..next_open_heap]) |*heap| {
        heap.deinit();
    }
    next_open_heap = 0;
}

pub fn createCustomType(custom_type: CustomType) ?*CustomType {
    var slot_index = undefined;
    if (cfg.threading) {
        slot_index = @atomicRmw(usize, &next_open_type, .Add, 1, .monotonic);
    } else {
        slot_index = next_open_heap;
        next_open_type += 1;
    }

    if (slot_index < cfg.max_custom_types) {
        custom_types[slot_index] = custom_type;
        return &custom_types[slot_index];
    } else {
        return null;
    }
}

test "Object duplication" {
    const ta = std.testing.allocator;
    var heap = (try createHeap(ta)) orelse return error.TestUnexpectedResult;
    defer deinitAll();

    // Number object
    const obj = try heap.createObject();
    defer heap.release(obj);
    var ref = peek(obj);
    ref.tag = .number;
    ref.body.number = 10;

    const new_obj = try heap.duplicate(obj);
    const new_ref = peek(new_obj);
    defer heap.release(new_obj);

    try expectEqual(.number, new_ref.tag);
    try expectEqual(10, new_ref.body.number);

    // try borrowing
    const borrowed = try heap.borrow(new_obj);
    try expectEqual(borrowed, new_obj);
    try expectEqual(2, heap.objects.get(new_obj.index).ref_count);

    heap.release(new_obj);
    try expectEqual(1, heap.objects.get(new_obj.index).ref_count);
}

test "Get string" {
    const ta = std.testing.allocator;
    var heap = (try createHeap(ta)) orelse return error.TestUnexpectedResult;
    defer deinitAll();

    const obj = try heap.createObject();
    defer heap.release(obj);
    var ref = peek(obj);
    ref.tag = .number;
    ref.body.number = 10;

    try expectEqualSlices(u8, "10", try getString(obj));
}

const DummyMutex = struct {
    fn lock(self: *DummyMutex) void {
        _ = self;
    }
    fn tryLock(self: *DummyMutex) void {
        _ = self;
    }
    fn unlock(self: *DummyMutex) void {
        _ = self;
    }
};
