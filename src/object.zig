const std = @import("std");
const math = std.math;

const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const string_utils = @import("string_utils.zig");
const buddy = @import("buddy.zig");

const null_string = 0;
const tiny_string = 1;
const empty_string = 2;

// align(16) is important, in order to be able to fit
// an Object pointer in a handle
const Object align(16) = packed struct {
    str_or_ptr: packed union {
        str: packed struct {
            index: u32,
            length: u26,
        },
        /// Be sure to >> 6 before setting, and << 6 when reading
        ptr: u58,
    },
    tag: Tag,
    is_long_string: bool,
    body: Body,
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
    string,
    list,
    reference,
    custom_type,
};

pub const LongString align(128) = struct {
    length: u64,
    utf8_length: ?u64,
    ref_count: usize,

    pub fn fromInt(int: u58) *LongString {
        return @ptrFromInt(int << 6);
    }

    pub fn toInt(ptr: *LongString) u58 {
        return @intFromPtr(ptr) >> 6;
    }

    pub fn incrRefCount(self: *LongString) void {
        if (multithreading) {
            _ = @atomicRmw(usize, &self.ref_count, .Add, 1, .monotonic);
        } else {
            self.ref_count += 1;
        }
    }

    pub fn decrRefCount(self: *LongString) void {
        if (multithreading) {
            _ = @atomicRmw(usize, &self.ref_count, .Sub, 1, .monotonic);
        } else {
            self.ref_count -= 1;
        }
    }
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
        /// Must be cast to [8]u8
        bytes: u64,
    },
    list: packed struct {
        index: u32,
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
    free_body: *const fn (bucket: ObjectBucket, obj: *Object) void,
    duplicate: *const fn (bucket: ObjectBucket, src: *Object, dest: *Object) void,
    get_string: *const fn (bucket: ObjectBucket, obj: *Object) Allocator.Error![:0]u8,
    make_immutable: *const fn (bucket: ObjectBucket, obj: *Object) void,
};

const Handle = packed struct {
    loc: struct {
        index: u32,
        bucket: u28,
    },
    flags: packed struct {
        /// Whether this object can be ref counted (else it needs to be cloned)
        ref_counted: bool,
        /// Whether the body can be shimmered (else it needs to be cloned)
        shimmerable: bool,
        /// Unused for now, may need another flag later.
        __unused_1: bool = false,
        /// Unused for now, may need another flag later.
        __unused_2: bool = false,
    },

    pub fn intToPtr(int: u60) *Object {
        return @ptrFromInt(int << 4);
    }

    pub fn ptrToInt(ptr: *Object) u60 {
        return @intFromPtr(ptr) >> 4;
    }
};

const BucketError = error{WrongBucket};
const multithreading = true;

pub const ObjectBucket = struct {
    const CustomTypeInstanceList = std.heap.MemoryPool(*anyopaque);
    const ObjectTracker = buddy.BuddyUnmanaged(32);
    const ObjectList = std.MultiArrayList(struct {
        object: Object,
        ref_count: u16,
        alloc_info: packed struct {
            order: u6,
            /// Whether this object is the front of the allocation
            /// (if not, this index should not be freed, as it's
            /// managed by another object)
            is_alloc_head: bool,
            _padding: u1 = 0,
        },
    });
    const StringTracker = buddy.BuddyUnmanaged(32);
    const StringList = std.ArrayList(u8);
    const RefCountList = std.ArrayList(u16);

    /// May point to self
    global_bucket: *ObjectBucket,
    /// Should only be in the global object bucket. Must not move
    /// locations after initialization.
    custom_types: []CustomType,

    gpa: Allocator,
    /// ID of 0 == global bucket
    bucket_id: u28,

    object_tracking: ObjectTracker,
    objects: ObjectList,
    string_tracking: StringTracker,
    strings: StringList,

    pub fn init(gpa: Allocator, bucket_id: u32) ObjectBucket {
        const object_tracking = try ObjectTracker.init(gpa, 32);
        errdefer object_tracking.deinit(gpa);
        const objects = try ObjectList.initCapacity(gpa, 32);
        errdefer objects.deinit(gpa);

        const string_tracking = try StringTracker.init(gpa, 32);
        errdefer string_tracking.deinit(gpa);
        const strings = try StringList.initCapacity(gpa, 32);
        errdefer strings.deinit(gpa);

        const ref_counts = try RefCountList.initCapacity(gpa, 32);
        errdefer ref_counts.deinit(gpa);

        const bucket: ObjectBucket = .{
            .gpa = gpa,
            .bucket_id = bucket_id,
            .object_tracking = object_tracking,
            .objects = objects,
            .string_tracking = string_tracking,
            .strings = strings,
            .ref_counts = ref_counts,
        };

        // null object is guaranteed to have index 0
        const null_object = try createObject(bucket);
        assert(null_object == 0);

        // null string is guaranteed to have index 0
        const null_string_idx = try createString(bucket, 1);
        assert(null_string_idx == null_string);
        // tiny string is guaranteed to have index 1
        const tiny_string_idx = try createString(bucket, 1);
        assert(tiny_string_idx == tiny_string);
        // empty string is guaranteed to have index 2
        const empty_string_idx = try createString(bucket, 1);
        assert(empty_string_idx == empty_string);

        return bucket;
    }

    pub fn deinit(self: *ObjectBucket) void {
        self.object_tracking.deinit(self.gpa);
        self.objects.deinit(self.gpa);
        self.string_tracking.deinit(self.gpa);
        self.strings.deinit(self.gpa);
        self.ref_counts.deinit(self.gpa);
    }

    pub fn createObject(self: *ObjectBucket) !u32 {
        return try self.createObjects(1);
    }

    /// create_objects does not initialize objects, but does initialize
    /// reference counts.
    pub fn createObjects(self: *ObjectBucket, count: u32) !u32 {
        const order = buddy.get_order(count);
        const index = try self.object_tracking.alloc(self.gpa, order);

        // Make sure arrays have space for new objects
        if (self.objects.len < index + count) {
            self.objects.resize(self.gpa, index + count);
        }

        // Initialize ref counts
        @memset(self.objects.items(.ref_count)[index..count], 1);

        // Initialize alloc info
        self.objects.items(.alloc_info)[index] = .{
            .order = order,
            .is_alloc_head = true,
        };

        if (count > 1) @memset(
            self.objects.items(.alloc_info)[(index + 1)..count],
            .{
                .order = order,
                .is_alloc_head = false,
            },
        );

        return index;
    }

    fn freeObjectRaw(self: *ObjectBucket, index: u32) !void {
        self.invalidateStringRaw(index);
        self.invalidateBodyRaw(index);

        const alloc_info = self.objects.get(index).alloc_info;
        if (alloc_info.is_alloc_head) {
            self.object_tracking.free(index, alloc_info.order);
        }
    }

    fn invalidateStringRaw(self: *ObjectBucket, index: u32) void {
        const obj = &self.objects.items(.object)[index];

        if (obj.is_long_string and obj.str_or_ptr.ptr != 0) {
            LongString.fromInt(obj.str_or_ptr.ptr).decrRefCount();
        } else if (!obj.is_long_string and obj.str_or_ptr.str.index > 2) {
            // Why ` > 2`? because it excludes all special string types
            self.freeString(obj.str_or_ptr.str.index, obj.str_or_ptr.str.length);
        }

        // Be sure to mark as having no string
        obj.is_long_string = false;
        obj.str_or_ptr.str = .{
            .index = 0,
            .length = 0,
        };
    }

    fn invalidateBodyRaw(self: *ObjectBucket, index: u32) void {
        const obj = &self.objects.items(.object)[index];

        switch (obj.tag) {
            .list => {
                const list = obj.body.list;

                for (0..list.length) |i| {
                    self.freeObjectRaw(list.index + i);
                }
            },
            .custom_type => {
                const custom_type = obj.body.custom_type;
                const type_fns = self.global_bucket.custom_types[custom_type.type_id];

                type_fns.free_body(self, obj);
            },
            .reference => {
                const target = obj.body.reference;
                self.release(target);
            },
            .string => {
                // How come string is a no-op? Because we could potentially
                // double-free when freeStringRep is called.
            },
            .none, .index, .return_code, .number, .float => {},
        }
    }

    fn createString(self: *ObjectBucket, length: usize) !usize {
        return try self.string_tracking.allocCount(self.gpa, length);
    }

    fn freeString(self: *ObjectBucket, index: u32, length: u32) void {
        self.string_tracking.freeCount(index, length);
    }

    fn duplicateObjString(self: *ObjectBucket, obj: *const Object) !Object {
        // Easy case: it doesn't have a string (null id or ptr)
        if ((obj.is_long_string and obj.str_or_ptr.ptr == 0) or
            (!obj.is_long_string and obj.str_or_ptr.str.index == null_string))
        {
            return .{
                .str_or_ptr = .{ .index = 0, .length = 0 },
                .tag = undefined,
                .is_long_string = false,
                .body = undefined,
            };
        }

        // Another easy case: tiny string (index = 1)
        if (!obj.is_long_string and obj.str_or_ptr.str.index == tiny_string) {
            return .{
                .str_or_ptr = obj.str_or_ptr,
                .tag = undefined,
                .is_long_string = false,
                .body = obj.body,
            };
        }

        if (obj.is_long_string) {
            // Reconstruct the pointer
            const long_string = LongString.fromInt(obj.str_or_ptr.ptr);
            long_string.incrRefCount();

            return .{
                .str_or_ptr = .{ .ptr = obj.str_or_ptr.ptr },
                .tag = undefined,
                .is_long_string = true,
                .body = undefined,
            };
        } else {
            // duplicate the string
            const old_string = obj.str_or_ptr.str;
            const new_string = if (old_string.length > 0) try self.createString(old_string.index) else empty_string;

            @memcpy(
                self.strings[new_string..(new_string + old_string.length)],
                self.strings[old_string.index..(old_string.index + old_string.length)],
            );

            return .{
                .str_or_ptr = .{
                    .str = .{
                        .index = new_string,
                        .length = old_string.length,
                    },
                },
                .tag = undefined,
                .is_long_string = false,
                .body = undefined,
            };
        }
    }

    fn duplicateSingle(self: *ObjectBucket, src: *const Object) !Object {
        switch (src.tag) {
            .none, .index, .return_code, .number, .float, .string => {
                const new_object = try self.duplicateObjString(src);
                new_object.tag = src.tag;
                new_object.body = src.body;
                return new_object;
            },
            .reference => {
                const ref = src.body.reference;
                const new_handle = try self.duplicate(ref);
                return .{
                    .str_or_ptr = .{
                        .str = .{ .index = 0, .length = 0 },
                    },
                    .tag = .reference,
                    .is_long_string = false,
                    .body = .{ .reference = new_handle },
                };
            },
            .custom_type => {
                const custom_type = src.body.custom_type;
                const type_fns = self.global_bucket.custom_types[custom_type.type_id];

                var new_object = try self.duplicateObjString(src);
                type_fns.duplicate(self, src, &new_object);

                return new_object;
            },
            .list => {
                @panic("duplicateSingle called with multi item object");
            },
        }
    }

    pub fn duplicate(self: *ObjectBucket, handle: Handle) !Handle {
        const src = try self.peek(handle);

        switch (src.tag) {
            .list => {
                const old_list = src.body.list;
                const new_list = try self.createObjects(1 + old_list.length);

                self.objects[new_list] = try self.duplicateObjString(handle);
                self.objects[new_list].tag = .list;
                self.objects[new_list].body.list = .{
                    .start = new_list + 1,
                    .length = old_list.length,
                };

                const old_start = old_list.index + 1;
                const old_end = old_list.index + 1 + old_list.length;
                const new_start = new_list + 1;
                const new_end = new_list + 1 + old_list.length;
                for (old_start..old_end, new_start..new_end) |old_i, new_i| {
                    self.objects[new_i] = try self.borrow(.{ .loc = .{ .index = .{ .index = old_i, .bucket = handl } } });
                }
            },
            else => {
                const new_object = try self.createObject();
                self.objects[new_object] = try self.duplicateSingle(src);
                return self.handle(new_object);
            },
        }
    }

    pub fn peek(self: *ObjectBucket, handle: Handle) !*Object {
        const loc = handle.loc;
        if (loc.bucket == self.bucket_id) {
            return &self.objects.items[loc.index];
        } else if (multithreading and loc.bucket == 0) {
            return &self.global_bucket.objects.items[loc.index];
        } else {
            return error.WrongBucket;
        }
    }

    pub fn borrow(self: *ObjectBucket, handle: Handle) !Handle {
        // If the object isn't ref counted, then we'll need to clone it
        if (!handle.flags.ref_counted) {
            return try self.duplicate(handle);
        }

        const loc = handle.loc;
        if (multithreading and loc.bucket == 0) {
            @atomicRmw(usize, &self.global_bucket.ref_counts[loc.index], .Add, 1, .monotonic);
        } else if (loc.bucket == self.bucket_id) {
            self.ref_counts[loc.index] += 1;
            return handle;
        } else {
            return error.WrongBucket;
        }
    }

    pub fn release(self: *ObjectBucket, handle: Handle) !void {
        if (!handle.flags.ref_counted) return;

        // If after_sub ends up as 0, then this object will be freed
        var after_sub: u32 = undefined;
        const loc = handle.loc;
        if (multithreading and loc.bucket == 0) {
            const before_sub = @atomicRmw(usize, &self.global_bucket.ref_counts[loc.index], .Sub, 1, .monotonic);
            after_sub = before_sub - 1;
        } else if (loc.bucket == self.bucket_id) {
            self.ref_counts[loc.index] -= 1;
            after_sub = self.ref_counts[loc.index];
        } else {
            return error.WrongBucket;
        }

        if (after_sub == 0) {
            self.invalidateStringRaw(loc);
            self.invalidateBodyRaw(loc);
        }
    }
};

test "Object duplication" {
    const ta = std.testing.allocator;

    // Number object
    var obj = init();
    obj.tag = .number;
    obj.body.number = 10;

    const new_obj = try obj.duplicate(ta);
    defer new_obj.release(ta);

    try expectEqual(.number, new_obj.tag);
    try expectEqual(10, new_obj.body.number);

    // try borrowing
    const borrowed = try new_obj.borrow(ta, false);
    try expectEqual(borrowed, new_obj);
    try expectEqual(2, new_obj.ref_count);

    borrowed.release(ta);
    try expectEqual(1, new_obj.ref_count);
}

pub const ObjectListRef = union(enum) {
    normal: *Body.List,
    dictionary: *Body.HashMap,

    pub fn get(self: *ObjectListRef, index: usize) *Object {
        switch (self.*) {
            .normal => |list| {
                return &list.elements[0..list.length][index];
            },
            .dictionary => |dict| {
                if (@rem(index, 2) == 0) {
                    return &dict.keys()[index / 2];
                } else {
                    return &dict.values()[index / 2];
                }
            },
        }
    }

    pub fn length(self: *ObjectListRef) usize {
        switch (self.*) {
            .normal => |list| return list.length,
            .dictionary => |dict| return dict.count() * 2,
        }
    }
};

fn getListString(allocator: Allocator, list: *ObjectListRef) ![:0]u8 {
    // Keep all the quoting results on the stack, if possible. If not,
    // we'll make an allocation.
    var quoting_types: []string_utils.QuotingType = undefined;
    var quoting_types_on_stack: [32]string_utils.QuotingType = undefined;
    if (list.length() > quoting_types_on_stack.len) {
        quoting_types = try allocator.alloc(string_utils.QuotingType, list.length());
    } else {
        quoting_types = quoting_types_on_stack[0..list.length()];
    }
    defer if (quoting_types.ptr != quoting_types_on_stack[0..].ptr) {
        allocator.free(quoting_types);
    };

    var total_length: usize = 0;
    for (0..list.length()) |i| {
        const element_string = try list.get(i).getString(allocator);
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

    var unfinished_str = try allocator.alloc(u8, total_length + 1);
    errdefer allocator.free(unfinished_str);
    var written: usize = 0;

    for (0..list.length()) |i| {
        const element_string = try list.get(i).getString(allocator);
        written += string_utils.quoteString(
            quoting_types[i],
            element_string,
            unfinished_str[written..],
            i == 0,
        );

        // Add a space (except at the end of the list)
        if (i + 1 < list.length()) {
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
    const finished_str = try allocator.realloc(unfinished_str, written);
    return finished_str[0..(written - 1) :0];
}

pub fn getString(obj: *Object, allocator: Allocator) Allocator.Error![:0]u8 {
    // Check if it already has a string representation
    if (obj.bytes) |bytes| {
        return bytes[0..obj.length :0];
    }

    // No representation, so we better generate it
    var new_str: [:0]u8 = undefined;
    switch (obj.tag) {
        .index => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{obj.body.index}, 0);
        },
        .return_code => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{obj.body.return_code}, 0);
        },
        .number => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{obj.body.number}, 0);
        },
        .float => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{obj.body.float}, 0);
        },
        .list => {
            var list = ObjectListRef{
                .normal = &obj.body.list,
            };
            new_str = try getListString(allocator, &list);
        },
        .dictionary => {
            var list = ObjectListRef{
                .dictionary = obj.body.dictionary.hash_map,
            };
            new_str = try getListString(allocator, &list);
        },
        .custom_type => {
            new_str = try obj.body.custom_type.type_ptr.get_string(allocator, obj);
        },
        .string, .none => {
            @panic("Tried to generate a string with no body");
        },
    }

    obj.bytes = new_str.ptr;
    obj.length = @truncate(new_str.len);
    return new_str;
}

test "Get string" {
    const ta = std.testing.allocator;

    var obj = init();
    obj.tag = .number;
    obj.body.number = 10;
    defer obj.freeInternals(ta);

    try expectEqualSlices(u8, "10", try obj.getString(ta));
}

/// Frees the string and body
pub fn freeInternals(obj: *Object, alloc: Allocator) void {
    obj.invalidateString(alloc);
    obj.invalidateBody(alloc);
}

pub fn invalidateString(obj: *Object, allocator: Allocator) void {
    if (obj.bytes) |bytes| {
        allocator.free(bytes[0..obj.length :0]);
        obj.bytes = null;
    }
}

/// Caller is responsible for syncing the body contents
/// across threads before calling.
pub fn invalidateBody(obj: *Object, alloc: Allocator) void {
    if (obj.tag == .none) return; // nothing to do

    switch (obj.tag) {
        .list => {
            const list = obj.body.list;

            for (0..list.length) |i| {
                list.elements[i].freeInternals(alloc);
            }

            alloc.free(list.elements[0..list.capacity]);
        },
        .dictionary => {
            const hash_map = obj.body.dictionary.hash_map;

            // Be sure to free the keys and values before freeing the container
            var iter = hash_map.iterator();
            while (iter.next()) |entry| {
                entry.key_ptr.freeInternals(alloc);
                entry.value_ptr.freeInternals(alloc);
            }

            hash_map.deinit(alloc);
        },
        .custom_type => {
            obj.body.custom_type.type_ptr.free_body(alloc, obj);
        },
        .string => {
            // How come string is a no-op? Because we could potentially
            // double-free when freeStringRep is called.
        },
        .none, .index, .return_code, .number, .float => {},
    }
}
