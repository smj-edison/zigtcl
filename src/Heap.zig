const std = @import("std");
const math = std.math;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const stringutil = @import("stringutil.zig");
const memutil = @import("memutil.zig");
const Parser = @import("Parser.zig");

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
    /// Maximum number of custom type instances.
    max_custom_type_instances: u32 = 65536,
    /// Maximum number of heaps (not necessarily initialized).
    max_heaps: usize = 128,
};
const cfg: HeapSettings = .{};

const Heap = @This();

const object_heap_max_count: usize = @as(usize, 1) << cfg.object_heap_order;
const object_heap_max_bytes: usize = ObjectList.capacityInBytes(object_heap_max_count);
const string_heap_max_bytes: usize = @as(usize, 1) << cfg.string_heap_order;

gpa: Allocator,
heap_id: HeapId,
/// Used whenever an allocation or free is happening
mem_mgmt_mutex: Mutex = .{},

object_tracking: ObjectTracker,
objects: ObjectList,
string_tracking: StringTracker,
strings: StringList,

type_instances: CustomTypeInstancePool,
parsed_scripts: ParsedScripts,

pub const HeapId = u30;
const Mutex = if (cfg.threading) std.Thread.Mutex else DummyMutex;

const ObjectTracker = memutil.BuddyUnmanaged(cfg.object_heap_order);
const ObjectList = std.MultiArrayList(ObjectAndMetadata);

const StringTracker = memutil.BuddyUnmanaged(cfg.string_heap_order);
const StringList = std.ArrayList(u8);

const CustomTypeInstance = struct {
    first_ptr: *anyopaque,
    second_ptr: *anyopaque,
};
const CustomTypeInstancePool = memutil.IndexedMemoryPool(CustomTypeInstance, cfg.use_vmem);

pub const TokenAndValue = struct {
    token: Parser.Token.Tag,
    value: union {
        int: i32,
        str: [:0]u8,
    },
};
/// Local to the interpreter. Not threadsafe.
const ParsedScript = struct {
    /// A handle pointing to a tcl list that has the same length as `tokens`,
    /// that stores the state of the evaluated script. Note, this is not
    /// the same as the stack.
    objects: Handle,
    /// Tokens array.
    tokens: []TokenAndValue,
    /// File name.
    filename: [:0]u8,
    /// Line number of the first line.
    first_line: u32,
    /// Ref count (starts at 1 when created).
    ref_count: u32,
};
const ParsedScripts = std.AutoHashMapUnmanaged(ScriptId, ParsedScript);

const Object = packed struct(u128) {
    pub const StrOrPtr = packed struct(u59) {
        u: packed union {
            str: packed struct {
                index: u32,
                len: u26,
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
            return self.str.u.str.index == 0 and self.str.u.str.len == 0;
        }
    }
};

comptime {
    assert(@sizeOf(Object) == 16);
}

pub const Tag = enum(u5) {
    none,
    index,
    number,
    float,
    bool,
    string,
    list,
    source,
    script,
    reference,
    custom_type,
};

/// Tcl list index. Indexes are inclusive both for start and end in tcl. Additionally,
/// an index may be relative, such as "end" or "end-1".
pub const ListIndex = packed struct {
    u: packed union {
        index: u32,
        end_offset: i33,
    },
    /// Whether this is the index "end", or "end-1", etc
    is_end: bool,

    pub const end: ListIndex = .{ .u = .{ .end_offset = 0 }, .is_end = true };

    pub fn asAbsoluteIndex(self: ListIndex, list_len: u32) !usize {
        if (self.is_end) {
            const idx = std.math.add(i33, self.u.end_offset, list_len -| 1) catch return error.BadIndex;
            if (idx < 0) return error.BadIndex;
            if (idx > list_len) return error.BadIndex;
            return @intCast(idx);
        } else {
            return self.u.index;
        }
    }
};

var next_open_script_id: u64 = 1;
/// Each script is assigned a unique id when created. Each interpreter
/// has a hashmap that associates a script with its local parsed
/// representation. This way, when a script is sent between threads,
/// the script doesn't need to be parsed twice. The script parsing
/// is not guaranteed to be idempotent.
pub const ScriptId = enum(u64) {
    null = 0,
    _,

    pub fn toInt(id: ScriptId) ?u64 {
        const as_int: u64 = @bitCast(id);

        if (as_int != 0) {
            return id;
        } else {
            return null;
        }
    }

    pub fn fromInt(id: ?u64) ScriptId {
        if (id) |unwrapped| {
            assert(unwrapped != 0);
            return @bitCast(unwrapped);
        } else {
            return ScriptId.null;
        }
    }

    pub fn next() ScriptId {
        return fromInt(atomicIncr(u64, &next_open_script_id));
    }
};

pub const Body = packed union {
    /// List index
    index: ListIndex,
    number: i64,
    float: f64,
    bool: bool,
    string: packed struct {
        /// If = utf8_length > maxInt(u32), it means the length has not been determined
        utf8_length: u33,
    },
    source: packed struct {
        /// Pointer to a nul-terminated string in the heap (we don't have
        /// space to store the string length, and file names can't have
        /// embedded nulls anyways)
        file_name: u32,
        line_no: u32,
    },
    list: packed struct {
        start: u32,
        len: u32,
    },
    script: packed struct {
        id: ScriptId,
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
    /// Type name.
    name: []u8,
    /// Must be threadsafe.
    invalidate_body: *const fn (heap: *Heap, obj: *Object) void,
    duplicate: *const fn (heap: *Heap, src: *const Object, dest: *Object) Allocator.Error!void,
    get_string: *const fn (heap: *Heap, obj: *const Object) Allocator.Error![:0]u8,
    make_immutable: *const fn (heap: *Heap, obj: *Object) Allocator.Error!void,
};

pub const Handle = packed struct(u64) {
    index: u32,
    heap: HeapId,
    /// Whether this object can be ref counted (else it needs to be cloned)
    ref_counted: bool,
    _padding: u1 = 0,

    pub fn format(
        self: Handle,
        writer: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        const str = getString(self) catch "<oom string>";
        try writer.writeAll(str);
    }
};

const ObjectAndMetadata = struct {
    object: Object,
    ref_count: u32,
    metadata: packed struct {
        /// Order can be u5 instead of u6, because the heap size must be < 2^32
        order: u5,
        /// Whether this object is the front of the allocation
        /// (if not, this index will not be freed, as it's
        /// managed by another object)
        is_alloc_head: bool,
        /// Whether this object is shared across threads
        cross_thread: bool,
        /// Whether this object is currently being used (used to track double frees)
        in_use: bool,
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
            memutil.vmemUnmap(@alignCast(objects.bytes[0..object_heap_max_bytes]));
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
    errdefer if (cfg.use_vmem) memutil.vmemUnmap(@alignCast(strings.items)) else strings.deinit(gpa);

    // Init type instances
    const type_instances_capacity = if (cfg.threading) cfg.max_custom_type_instances else 32;
    var type_instances: CustomTypeInstancePool = try .initWithCapacity(gpa, type_instances_capacity);
    errdefer type_instances.deinit(gpa);

    var parsed_scripts: ParsedScripts = .{};
    errdefer parsed_scripts.deinit(gpa);

    // Create heap
    var heap = Heap{
        .gpa = gpa,
        .heap_id = heap_id,

        .object_tracking = object_tracking,
        .objects = objects,
        .string_tracking = string_tracking,
        .strings = strings,

        .type_instances = type_instances,
        .parsed_scripts = parsed_scripts,
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
    for (0..self.objects.len) |i| {
        if (self.objects.get(i).metadata.in_use) {
            self.freeObject(.{ .index = @intCast(i), .heap = self.heap_id, .ref_counted = undefined });
        }
    }

    if (cfg.use_vmem) {
        memutil.vmemUnmap(@alignCast(self.strings.items));
        memutil.vmemUnmap(@alignCast(self.objects.bytes[0..object_heap_max_bytes]));
    } else {
        // Don't use self.heapAlloc() in this case, as that will error
        // with the null allocator
        self.strings.deinit(self.gpa);
        self.objects.deinit(self.gpa);
    }
    self.object_tracking.deinit(self.gpa);
    self.string_tracking.deinit(self.gpa);

    self.type_instances.deinit(self.gpa);
    self.parsed_scripts.deinit(self.gpa);
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
    const order: u5 = @intCast(memutil.getOrder(count));

    self.mem_mgmt_mutex.lock();
    errdefer self.mem_mgmt_mutex.unlock();
    const index: u32 = @intCast(try self.object_tracking.alloc(self.gpa, order));
    self.mem_mgmt_mutex.unlock();

    const end = index + count;

    // Make sure arrays have space for new objects
    if (self.objects.len < index + count) {
        const start_of_new = self.objects.len;
        try self.objects.resize(self.heapAlloc(), index + count);
        @memset(self.objects.items(.object)[start_of_new..self.objects.len], .{
            .str = .{
                .u = .{ .str = .{ .index = 0, .len = 0 } },
                .is_ptr = false,
            },
            .tag = .none,
            .body = .{
                .number = 0,
            },
        });
    }

    // Make sure the items we're allocating are free (used to
    // ensure our allocator hasn't reached a broken state).
    // Might not be necessary.
    for (self.objects.items(.metadata)[index..end]) |metadata| {
        assert(metadata.in_use == false);
    }

    // Initialize all as empty objects
    @memset(self.objects.items(.object)[index..end], .{
        .str = .{
            .u = .{ .str = .{ .index = 0, .len = 0 } },
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
        .in_use = true,
    };

    if (count > 1) @memset(
        self.objects.items(.metadata)[(index + 1)..end],
        .{
            .order = order,
            .is_alloc_head = false,
            .cross_thread = false,
            .in_use = true,
        },
    );

    return index;
}

fn freeObject(calling_heap: *Heap, handle: Handle) void {
    const obj_heap = getHeap(handle);

    calling_heap.invalidateBody(handle);
    calling_heap.invalidateString(handle);

    const metadata = obj_heap.objects.get(handle.index).metadata;
    if (metadata.is_alloc_head) {
        obj_heap.mem_mgmt_mutex.lock();
        obj_heap.object_tracking.free(handle.index, metadata.order);
        obj_heap.objects.items(.metadata)[handle.index].in_use = false;
        obj_heap.mem_mgmt_mutex.unlock();
    }
}

pub fn getHeap(handle: Handle) *Heap {
    return &heaps[handle.heap];
}

pub fn canShimmer(handle: Handle) bool {
    // Can't shimmer if it's shared between threads
    return !getHeap(handle).objects.get(handle.index).metadata.cross_thread;
}

/// If the object can't be shimmered, this will duplicate said object
/// and release the original object.
pub fn ensureShimmerable(calling_heap: *Heap, handle: *Handle) !void {
    if (!Heap.canShimmer(handle.*)) {
        const before_duplicating = handle.*;
        handle.* = try calling_heap.duplicate(handle.*);
        calling_heap.release(before_duplicating);
    }
}

pub fn invalidateString(calling_heap: *Heap, handle: Handle) void {
    _ = calling_heap;
    getHeap(handle).invalidateLocalString(handle.index);
}

/// `calling_heap` _must_ be the heap that this is being called from,
/// _not_ the handle's heap. Used to guarantee safe freeing of
/// non-threadsafe objects.
pub fn invalidateBody(calling_heap: *Heap, handle: Handle) void {
    const obj_heap = getHeap(handle);
    const obj: *Object = &obj_heap.objects.items(.object)[handle.index];

    switch (obj.tag) {
        .list => {
            const list = obj.body.list;

            for (0..list.len) |i| {
                obj_heap.freeObject(.{ .index = @intCast(i), .heap = handle.heap, .ref_counted = undefined });
            }
        },
        .custom_type => {
            const custom_type = obj.body.custom_type;
            const type_fns = custom_types[custom_type.type_id];

            type_fns.invalidate_body(obj_heap, obj);
        },
        .reference => {
            const target = obj.body.reference;
            obj_heap.release(target);
        },
        .string => {
            // How come string is a no-op? Because we could potentially
            // double-free when freeStringRep is called.
        },
        .script => {
            const script = obj.body.script; // copy
            obj.body.script.id = .null;

            // If we're not in the same heap, we can't safely free the script.
            if (calling_heap != obj_heap) return;

            _ = obj_heap.parsed_scripts.remove(script.id);
        },
        .source => {
            const source = obj.body.source;
            const file_name = obj_heap.getHeapStringZ(source.file_name);
            obj_heap.freeString(source.file_name, @intCast(file_name.len));
        },
        .none, .index, .number, .float, .bool => {},
    }
}

fn invalidateLocalString(self: *Heap, index: u32) void {
    const obj: *Object = &self.objects.items(.object)[index];

    switch (self.getLocalStringDetails(index)) {
        .long => |long_str| {
            long_str.decrRefCount(self.gpa);
        },
        .normal => {
            self.freeString(obj.str.u.str.index, obj.str.u.str.len);
        },
        .null, .empty => {},
    }

    // Be sure to mark as having no string
    obj.str.is_ptr = false;
    obj.str.u.str = .{
        .index = 0,
        .len = 0,
    };
}

/// Get a string slice from heap string storage
pub fn getHeapString(self: *Heap, start: u32, end: u32) [:0]u8 {
    return self.strings.items[start..end :0];
}

/// Get a null-terminated string from heap string storage starting at index
pub fn getHeapStringZ(self: *Heap, index: u32) [:0]u8 {
    const ptr: [*:0]u8 = @ptrCast(&self.strings.items[index]);
    return std.mem.span(ptr);
}

/// Allocates 1 + length, in order to make space for the null byte
pub fn createString(self: *Heap, len: u32) !u32 {
    const length_with_null = len + 1;
    self.mem_mgmt_mutex.lock();
    defer self.mem_mgmt_mutex.unlock();
    const new_string: u32 = @intCast(try self.string_tracking.allocCount(self.gpa, length_with_null));
    self.strings.items[new_string + len] = 0;
    return new_string;
}

pub fn freeString(self: *Heap, index: u32, len: u32) void {
    const length_with_null = len + 1;
    self.mem_mgmt_mutex.lock();
    self.string_tracking.freeCount(index, length_with_null);
    self.mem_mgmt_mutex.unlock();
}

/// Increase ref count if possible, otherwise duplicate.
pub fn borrow(calling_heap: *Heap, handle: Handle) !Handle {
    // If the object isn't ref counted, then we'll need to clone it (i.e. a list item)
    if (!handle.ref_counted) {
        return try calling_heap.duplicate(handle);
    }

    // This object may have come from another heap
    const obj_heap = getHeap(handle);

    incrRefCountOf(u32, &obj_heap.objects.items(.ref_count)[handle.index]);

    return handle;
}

pub fn release(calling_heap: *Heap, handle: Handle) void {
    if (!handle.ref_counted) return;

    // This object may have come from another heap
    var heap = getHeap(handle);

    if (decrRefCountOf(u32, &heap.objects.items(.ref_count)[handle.index])) {
        calling_heap.freeObject(handle);
    }
}

fn duplicateObjString(calling_heap: *Heap, handle: Handle) !Object.StrOrPtr {
    switch (getStringDetails(handle)) {
        .long => |long_str| {
            long_str.incrRefCount();
            return .{
                .u = .{ .ptr = LongString.toInt(long_str) },
                .is_ptr = true,
            };
        },
        .normal => |bytes| {
            const new_string = try calling_heap.createString(@intCast(bytes.len));
            const len: u26 = @intCast(bytes.len);
            @memcpy(calling_heap.getHeapString(new_string, new_string + len), bytes);

            return .{
                .u = .{ .str = .{ .index = new_string, .len = len } },
                .is_ptr = false,
            };
        },
        .null, .empty => {
            return peek(handle).str;
        },
    }
}

fn duplicateSingle(self: *Heap, handle: Handle) !Object {
    const src = peek(handle);
    switch (src.tag) {
        .none, .index, .number, .float, .string, .bool, .script => {
            return .{
                .str = try self.duplicateObjString(handle),
                .tag = src.tag,
                .body = src.body,
            };
        },
        .source => {
            // Duplicate the source info, including the filename string
            const source = src.body.source;
            const file_name = self.getHeapStringZ(source.file_name);
            const len: u26 = @intCast(file_name.len);

            const new_file_name = try self.createString(len);
            errdefer self.freeString(new_file_name, len);

            @memcpy(self.getHeapString(new_file_name, new_file_name + len), file_name);

            return .{
                .str = try self.duplicateObjString(handle),
                .tag = .source,
                .body = .{
                    .source = .{
                        .file_name = new_file_name,
                        .line_no = source.line_no,
                    },
                },
            };
        },
        .reference => {
            const ref = src.body.reference;
            const new_handle = try self.borrow(ref);
            return .{
                .str = .{
                    .u = .{ .str = .{ .index = 0, .len = 0 } },
                    .is_ptr = false,
                },
                .tag = .reference,
                .body = .{ .reference = new_handle },
            };
        },
        .custom_type => {
            const custom_type = src.body.custom_type;

            var new_object: Object = .{
                // TODO make sure this doesn't leak
                .str = try self.duplicateObjString(handle),
                .tag = .custom_type,
                .body = .{
                    .custom_type = .{
                        .index = try self.createCustomTypeInstance(),
                        .type_id = custom_type.type_id,
                    },
                },
            };
            try custom_types[custom_type.type_id].duplicate(self, src, &new_object);

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

            const new_list_idx = try self.createObjects(1 + old_body.len);
            errdefer {
                // Iterate in reverse order to prevent freeing the head of the list first
                var i = new_list_idx + 1 + old_body.len;
                while (i > 0) {
                    i -= 1;
                    self.release(self.normalHandle(i));
                }
            }
            const new_head: *Object = &self.objects.items(.object)[new_list_idx];
            const new_start = new_list_idx + 1;
            const new_end = new_start + old_body.len;
            var new_items = self.objects.items(.object)[new_start..new_end];

            // Duplicate head of list
            new_head.* = .{
                .str = try self.duplicateObjString(handle),
                .tag = .list,
                .body = .{
                    .list = .{
                        .start = new_list_idx + 1,
                        .len = old_body.len,
                    },
                },
            };

            // Duplicate items of list
            var i: usize = 0;
            while (i < old_body.len) : (i += 1) {
                new_items[i] = try self.duplicateSingle(.{
                    .heap = handle.heap,
                    .index = @intCast(old_body.start + i),
                    .ref_counted = false,
                });
            }

            return self.normalHandle(new_list_idx);
        },
        else => {
            const new_object = try self.createObject();
            self.objects.items(.object)[new_object.index] = try self.duplicateSingle(handle);
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
    return getHeap(handle).getLocalObject(handle.index);
}

pub fn getLocalObject(self: *Heap, index: u32) *Object {
    return &self.objects.items(.object)[index];
}

/// Guaranteed to be valid, barring OOM.
pub fn getString(handle: Handle) ![:0]const u8 {
    return try getHeap(handle).getLocalString(handle.index);
}

/// Get the string to modify (must not write any longer than current len).
/// Not threadsafe.
pub fn getStringMut(handle: Handle) ![:0]u8 {
    const heap = getHeap(handle);
    try heap.getLocalString(handle.index); // generate rep

    const obj = heap.getLocalObject(handle.index);
    switch (heap.getLocalStringDetails(handle.index)) {
        .long => |long_str| {
            return &long_str.string;
        },
        .normal => {
            const str = obj.str.u.str;
            return heap.getHeapString(str.index, str.index + str.len);
        },
        .null, .empty => return error.NotMutable,
    }
}

/// Copies provided string.
pub fn setString(handle: Handle, bytes: []const u8) !void {
    const heap = getHeap(handle);
    // TODO optimize, we shouldn't copy the string twice (I
    // probably need to redesign the `setLocalString` API)
    const new_str = try heap.gpa.dupeZ(u8, bytes);
    errdefer heap.gpa.free(new_str);
    const took_ownership = try heap.setLocalString(handle.index, new_str);
    if (!took_ownership) heap.gpa.free(new_str);
}

/// Returns whether it took ownership of the bytes. Threadsafe.
fn setLocalString(self: *Heap, index: usize, bytes: [:0]u8) !bool {
    var took_ownership = false;

    // Figure out the best way to represent the string
    var new_str_or_ptr: Object.StrOrPtr = undefined;
    if (bytes.len == 0) {
        new_str_or_ptr.u.str = .{
            .index = empty_string,
            .len = 0,
        };
        new_str_or_ptr.is_ptr = false;
    } else if (bytes.len < LongString.split_point) {
        const local_string = try self.createString(@intCast(bytes.len));
        const len: u26 = @intCast(bytes.len);
        @memcpy(
            self.getHeapString(local_string, local_string + len),
            bytes,
        );

        new_str_or_ptr.u.str = .{
            .index = local_string,
            .len = len,
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
                    LongString.fromInt(new_str_or_ptr.u.ptr).freeUnchecked(self.gpa);
                } else {
                    const local_string = new_str_or_ptr.u.str;
                    if (local_string.index > 1) {
                        self.freeString(local_string.index, local_string.len);
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

    switch (self.getLocalStringDetails(index)) {
        .long => |long_str| {
            return long_str.string;
        },
        .normal => |str| {
            return str;
        },
        .empty => {
            return empty_string_value;
        },
        .null => {
            // Keep going in code
        },
    }

    // No representation, so we better generate it
    var new_str: [:0]u8 = undefined;
    switch (obj.tag) {
        .index => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.index}, 0);
        },
        .number => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.number}, 0);
        },
        .float => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{obj.body.float}, 0);
        },
        .bool => {
            new_str = try std.fmt.allocPrintSentinel(self.gpa, "{}", .{@intFromBool(obj.body.bool)}, 0);
        },
        .list => {
            const list = obj.body.list;
            new_str = try getListString(self, list.start, list.len);
        },
        .custom_type => {
            const custom_type = obj.body.custom_type;
            new_str = try custom_types[custom_type.type_id].get_string(self, obj);
        },
        .reference => {
            return getString(obj.body.reference);
        },
        .source, .script => {
            @panic("Source and script objects should always have a string representation");
        },
        .string, .none => {
            @panic("Tried to generate a string with no body");
        },
    }

    const took_ownership = try self.setLocalString(index, new_str);
    if (!took_ownership) self.gpa.free(new_str);

    // Rerun this function to figure out where the new string is
    return self.getLocalString(index);
}

fn getListString(self: *Heap, index: u32, len: u32) ![:0]u8 {
    var fallback = std.heap.stackFallback(64, self.gpa);
    var stack_alloc = fallback.get();
    var quoting_types = try stack_alloc.alloc(stringutil.QuotingType, len);
    defer stack_alloc.free(quoting_types);

    // Step 1: calculate the string length.
    var total_length: usize = 0;
    for (0..len) |i| {
        const element_string = try self.getLocalString(@intCast(index + i));
        quoting_types[i] = stringutil.calculateNeededQuotingType(element_string);
        if (i == 0 and quoting_types[i] == .bare and
            element_string.len > 0 and element_string[0] == '#')
        {
            // Make sure the first element has # escaped in braces
            quoting_types[i] = .brace;
        }
        total_length += stringutil.quoteSize(quoting_types[i], element_string.len);
        total_length += 1; // space between each element
    }

    // Step 2: actually create said string.
    var unfinished_str = try self.gpa.alloc(u8, total_length + 1);
    errdefer self.gpa.free(unfinished_str);
    var written: usize = 0;

    for (0..len) |i| {
        const element_string = try self.getLocalString(@intCast(index + i));
        written += stringutil.quoteString(
            quoting_types[i],
            element_string,
            unfinished_str[written..],
            i == 0,
        );

        // Add a space (except at the end of the list)
        if (i + 1 < len) {
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
    normal: [:0]u8,
    long: *align(LongString.align_amt) LongString,
};

pub fn getStringDetails(handle: Handle) StringDetails {
    return getHeap(handle).getLocalStringDetails(handle.index);
}

fn getLocalStringDetails(self: *Heap, index: u32) StringDetails {
    const obj = self.getLocalObject(index);

    // Normal string or long string?
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
                .normal = self.getHeapString(str.index, str.index + str.len),
            };
        }
    }
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
        incrRefCountOf(usize, &self.ref_count);
    }

    pub fn decrRefCount(self: *align(align_amt) LongString, gpa: Allocator) void {
        if (decrRefCountOf(usize, &self.ref_count)) {
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
        const slot_index = atomicIncr(usize, &self.next_open);

        if (slot_index < cfg.max_custom_types) {
            return slot_index;
        } else {
            return null;
        }
    }
};

pub fn createCustomTypeInstance(self: *Heap) !u32 {
    self.mem_mgmt_mutex.lock();
    defer self.mem_mgmt_mutex.unlock();

    const new_id = try self.type_instances.create(self.gpa);
    if (new_id >= cfg.max_custom_type_instances) return error.OutOfMemory;

    return @intCast(new_id);
}

/// `tokens` must be allocated by the allocator provided to heap. Takes ownership.
pub fn createParsedScript(self: *Heap, script: ParsedScript) !void {
    const index = try self.parsed_scripts.create(self.gpa);
    self.parsed_scripts.items[index] = script;
}

// Heap instances //
pub var heaps: [cfg.max_heaps]Heap = undefined;
var next_open_heap: usize = 0;
pub var custom_types: [cfg.max_custom_types]CustomType = undefined;
var next_open_type: usize = 0;

pub fn createHeap(gpa: Allocator) !*Heap {
    const slot_index = atomicIncr(usize, &next_open_heap);

    if (slot_index < cfg.max_heaps) {
        heaps[slot_index] = try init(gpa, @intCast(slot_index));
        return &heaps[slot_index];
    } else {
        return error.OutOfMemory;
    }
}

pub fn deinitAll() void {
    for (heaps[0..next_open_heap]) |*heap| {
        heap.deinit();
    }
    next_open_heap = 0;
}

pub fn createCustomType(custom_type: CustomType) ?*CustomType {
    const slot_index = atomicIncr(usize, &next_open_type);

    if (slot_index < cfg.max_custom_types) {
        custom_types[slot_index] = custom_type;
        return &custom_types[slot_index];
    } else {
        return null;
    }
}

test "Object duplication" {
    const ta = std.testing.allocator;
    var heap = try createHeap(ta);
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
    var heap = try createHeap(ta);
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

/// Atomically adds, if multithreading is enabled. Returns value before adding.
pub fn atomicIncr(comptime T: type, ptr: *T) T {
    if (cfg.threading) {
        return @atomicRmw(T, ptr, .Add, 1, .monotonic);
    } else {
        const before = ptr.*;
        ptr.* += 1;
        return before;
    }
}

pub fn incrRefCountOf(comptime T: type, ref: *T) void {
    if (cfg.threading) {
        _ = @atomicRmw(T, ref, .Add, 1, .monotonic);
    } else {
        ref.* += 1;
    }
}

/// Returns true if count has reached zero. Multithreaded safe.
/// Happens-after the previous decrement.
pub fn decrRefCountOf(comptime T: type, ref: *T) bool {
    var after_sub: T = undefined;
    if (cfg.threading) {
        const before_sub = @atomicRmw(T, ref, .Sub, 1, .release);
        after_sub = before_sub - 1;

        if (after_sub == 0) {
            _ = @atomicLoad(T, ref, .acquire);
        }
    } else {
        ref.* -= 1;
        after_sub = ref.*;
    }

    return after_sub == 0;
}
