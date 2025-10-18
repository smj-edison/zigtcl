const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const string_utils = @import("string_utils.zig");

/// String representation of value
bytes: ?[*:0]u8 = null,
/// Length of string in bytes
length: u32 = 0,
/// If flags.cross_thread = true, only atomic operations will be used
ref_count: u32,
flags: packed struct {
    /// Whether this object can be ref counted (else it needs to be cloned)
    ref_counted: bool,
    /// If shared across threads
    cross_thread: bool = false,
    /// Whether the body can be mutated (else it needs to be cloned)
    mutable: bool,
},
/// Type of object
tag: Tag = .none,
body: Body,

comptime {
    assert(@sizeOf(Object) <= 64);
}

const Object = @This();

pub const CustomType = struct {
    name: []u8, // Type name
    free_body: *const fn (allocator: Allocator, obj: *Object) void,
    duplicate: *const fn (allocator: Allocator, src: *Object, dest: *Object) void,
    get_string: *const fn (allocator: Allocator, obj: *Object) Allocator.Error![:0]u8,
    make_immutable: *const fn (allocator: Allocator, obj: *Object) void,
};

pub const Tag = enum(u5) {
    none,
    index,
    return_code,
    number,
    float,
    string,
    dictionary,
    list,
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
    list: List,
    dictionary: packed struct {
        /// Every object must have a pregenerated string representation in the hash map
        hash_map: *HashMap,
    },
    custom_type: packed struct {
        type_ptr: *CustomType,
        value: *anyopaque,
    },

    const List = packed struct {
        elements: [*]Object,
        capacity: u32,
        length: u32,
    };
    const CompactList = packed struct {
        elements: [*]Body,
        capacity: u32,
        length: u32,
    };

    pub const HashMap = std.ArrayHashMapUnmanaged(Object, Object, ObjContext, true);
    pub const ObjContext = struct {
        pub fn hash(self: ObjContext, obj: Object) u32 {
            _ = self;
            return std.array_hash_map.hashString(obj.bytes.?[0..obj.length]);
        }

        pub fn eql(self: ObjContext, a: Object, b: Object) bool {
            _ = self;
            return std.array_hash_map.eqlString(
                a.bytes.?[0..a.length],
                b.bytes.?[0..b.length],
            );
        }
    };
};

comptime {
    assert(@sizeOf(Body) == 16);
}

pub fn init() Object {
    return .{
        .ref_count = 1,
        .flags = .{
            .mutable = true,
            // Not ref counted, because it's currently living on
            // the stack.
            .ref_counted = false,
        },
        .body = undefined,
    };
}

pub fn initAlloc(allocator: Allocator) !*Object {
    const obj = try allocator.create(Object);

    obj.* = .{
        .ref_count = 1,
        .flags = .{
            .mutable = true,
            .ref_counted = true,
        },
        .body = undefined,
    };

    return obj;
}

/// Releases an object that's on the stack.
pub fn deinit(obj: *Object, alloc: Allocator) void {
    invalidateString(alloc, obj);
    invalidateBody(alloc, obj);
    // Don't free the head or body, since they're on the stack
}

pub fn borrow(
    obj: *Object,
    allocator: Allocator,
    /// Whether to release the original ref if duplicated
    release_original: bool,
) !*Object {
    if (obj.flags.ref_counted) {
        if (obj.flags.cross_thread) {
            _ = @atomicRmw(u32, &obj.ref_count, .Add, 1, .monotonic);
        } else {
            obj.ref_count += 1;
        }

        return obj;
    } else {
        // Duplicate object, as it can't be referenced
        const new_object = try obj.duplicate(allocator);
        if (release_original) obj.release(allocator);
        return new_object;
    }
}

/// Releases an object. No operation if flags.ref_counted = false.
/// Use `deinit` if object is on the stack.
pub fn release(obj: *Object, alloc: Allocator) void {
    // TODO: profile whether branchless or branched is better
    const sub_by: u32 = @intFromBool(obj.flags.ref_counted);
    var after_sub: u32 = 0;

    // Make sure to use atomic operations if it's threaded
    if (obj.flags.cross_thread) {
        const before_sub = @atomicRmw(u32, &obj.ref_count, .Sub, sub_by, .release);
        after_sub = before_sub - 1;

        if (after_sub == 0) {
            _ = @atomicLoad(u32, &obj.ref_count, .acquire);
        }
    } else {
        obj.ref_count -= sub_by;
        after_sub = obj.ref_count;
    }

    if (after_sub == 0) {
        // We'll never reach here if it's on the stack, since its ref_count
        // was initialized to 1, and sub_by would be 0.
        obj.freeInternals(alloc);
        alloc.destroy(obj);
    }
}

pub fn duplicateOnto(src: *Object, allocator: Allocator, dest: *Object) !void {
    assert(dest.bytes == null);
    if (src.bytes) |to_copy| {
        const new_string = try allocator.dupeZ(u8, to_copy[0..src.length]);
        dest.bytes = new_string.ptr;
        dest.length = src.length;
    }
    errdefer if (dest.bytes) |bytes| allocator.free(bytes[0..src.length]);

    switch (src.tag) {
        .list => {
            const list = src.body.list;
            const new_list = try allocator.dupe(Object, list.elements[0..list.length]);
            errdefer allocator.free(new_list);

            dest.body.list = .{
                .elements = new_list.ptr,
                .capacity = list.length,
                .length = list.length,
            };
        },
        .dictionary => {
            const hash_map = src.body.dictionary.hash_map;
            var new_hash_map = try Body.HashMap.init(allocator, hash_map.keys(), hash_map.values());

            // initialize new values
            var i: usize = 0;
            while (i < hash_map.count()) : (i += 1) {
                try hash_map.keys()[i].duplicateOnto(allocator, &new_hash_map.keys()[i]);
                try hash_map.values()[i].duplicateOnto(allocator, &new_hash_map.values()[i]);
            }
            errdefer {
                for (0..i) |j| {
                    freeInternals(allocator, &new_hash_map.keys()[j]);
                    freeInternals(allocator, &new_hash_map.values()[j]);
                }
            }

            dest.body.dictionary.hash_map = &new_hash_map;
        },
        .custom_type => {
            src.body.custom_type.type_ptr.duplicate(allocator, src, dest);
        },
        .string, .index, .return_code, .number, .float => {
            dest.body = src.body;
        },
        .none => {},
    }

    dest.tag = src.tag;
}

pub fn duplicate(src: *Object, allocator: Allocator) !*Object {
    const new_obj = try allocator.create(Object);

    new_obj.* = .{
        .ref_count = 1,
        .flags = .{
            .ref_counted = true,
            .mutable = true,
        },
        .body = undefined,
    };

    try src.duplicateOnto(allocator, new_obj);
    return new_obj;
}

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
