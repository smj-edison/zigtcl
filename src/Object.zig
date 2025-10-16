const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const expectEqual = std.testing.expectEqual;
const expectEqualSlices = std.testing.expectEqualSlices;

const string_utils = @import("string_utils.zig");

head: Head,
body: Body,

const Object = @This();

pub const TypeFlags = packed struct {
    /// Can this type be in a compact list?
    compactable: bool,
};
pub const CustomType = struct {
    name: []u8, // Type name
    free_body: *const fn (allocator: Allocator, ref: Ref) void,
    duplicate: *const fn (allocator: Allocator, src: Ref, dest: Ref) void,
    get_string: *const fn (allocator: Allocator, obj: Ref) Allocator.Error![:0]u8,
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
    /// Non-compact list
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
        /// bytes should always equal Head.bytes (why deduplicate? in case
        /// there's a compact list of strings--the Head is not stored)
        bytes: ?[*:0]u8,
        byte_length: u32,
        /// If = maxInt(u32), it means the length has not been determined
        utf8_length: u32,
    },
    list: List,
    /// Compact list stores only the body
    compact_list: CompactList,
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
            return std.array_hash_map.hashString(obj.head.bytes.?[0..obj.head.length]);
        }

        pub fn eql(self: ObjContext, a: Object, b: Object) bool {
            _ = self;
            return std.array_hash_map.eqlString(
                a.head.bytes.?[0..a.head.length],
                b.head.bytes.?[0..b.head.length],
            );
        }
    };
};

comptime {
    assert(@sizeOf(Body) == 16);
}

pub const Head = packed struct {
    /// String representation of value
    bytes: ?[*:0]u8 = null,
    /// Length of string in bytes
    length: u32 = 0,
    /// If flags.cross_thread = true, only atomic operations will be used
    ref_count: u32,
    /// Whether this object can be ref counted (else it needs to be cloned)
    ref_counted: bool,
    /// If shared across threads
    cross_thread: bool = false,
    /// Whether the body can be mutated (else it needs to be cloned)
    mutable: bool,
    /// Whether this is a compact list (if so, ObjHead.tag is not the type,
    /// but the list element's body type)
    is_compact_list: bool,
    /// Whether this is a synthetic head (e.g. not from an object)
    is_synthetic: bool,
    /// Type of object, or type of list elements, if flags.is_compact_list is true
    tag: Tag = .none,

    comptime {
        assert(@sizeOf(Head) <= 32);
    }
};

pub fn init() Object {
    return .{
        .head = .{
            .ref_count = 1,
            .mutable = true,
            // Not ref counted, because it's currently living on
            // the stack.
            .ref_counted = false,
            .is_compact_list = false,
            .is_synthetic = false,
        },
        .body = undefined,
    };
}

pub fn initAlloc(allocator: Allocator) !*Object {
    var obj = try allocator.alignedAlloc(Object, null, 1)[0];

    obj.head = .{
        .ref_count = 1,
        .mutable = true,
        .ref_counted = true,
        .is_compact_list = false,
        .is_synthetic = false,
    };

    return obj;
}

pub const Ref = struct {
    head: *Head,
    body: *Body,

    pub fn borrow(
        self: Ref,
        allocator: Allocator,
        /// Whether to release the original ref if duplicated
        release_original: bool,
    ) !Ref {
        return Object.borrow(allocator, self, release_original);
    }

    pub fn release(self: Ref, allocator: Allocator) void {
        Object.release(allocator, self);
    }
};

pub const ConstRef = struct {
    head: *const Head,
    body: *const Body,
};

/// Releases an object that's on the stack.
pub fn deinit(obj: Object, alloc: Allocator) void {
    invalidateString(alloc, obj.asRef());
    invalidateBody(alloc, obj.asRef());
    // Don't free the head or body, since they're on the stack
}

pub fn borrow(
    allocator: Allocator,
    ref: Ref,
    /// Whether to release the original ref if duplicated
    release_original: bool,
) !Ref {
    if (ref.head.ref_counted) {
        if (ref.head.cross_thread) {
            _ = @atomicRmw(u32, &ref.head.ref_count, .Add, 1, .monotonic);
        } else {
            ref.head.ref_count += 1;
        }

        return ref;
    } else {
        // Duplicate object, as it can't be referenced
        const new_object = try duplicate(allocator, ref);
        if (release_original) release(allocator, ref);
        return new_object;
    }
}

/// Releases an object reference. No operation if flags.ref_counted = false.
/// Use `deinit` if object is on the stack.
pub fn release(alloc: Allocator, ref: Ref) void {
    // TODO: profile whether branchless or branched is better
    const sub_by: u32 = @intFromBool(ref.head.ref_counted);
    var after_sub: u32 = 0;

    // Make sure to use atomic operations if it's threaded
    if (ref.head.cross_thread) {
        const before_sub = @atomicRmw(u32, &ref.head.ref_count, .Sub, sub_by, .release);
        after_sub = before_sub - 1;

        if (after_sub == 0) {
            _ = @atomicLoad(u32, &ref.head.ref_count, .acquire);
        }
    } else {
        ref.head.ref_count -= sub_by;
        after_sub = ref.head.ref_count;
    }

    if (after_sub == 0) {
        // We'll never reach here if it's on the stack, since its ref_count
        // was initialized to 1, and sub_by would be 0.
        freeInternals(alloc, ref);
        const obj_ptr: *Object = @fieldParentPtr("head", ref.head);
        const original_ptr: [*:0]u8 = @ptrCast(obj_ptr);
        const original_slice = original_ptr[0..size(ref)];
        alloc.rawFree(original_slice, std.mem.Alignment.of(Object), @returnAddress());
    }
}

pub fn duplicateOnto(allocator: Allocator, src: Ref, dest: Ref) !void {
    const bytes_to_copy: ?[:0]u8 = blk: {
        if (src.head.is_synthetic) {
            if (src.head.tag == .string and src.body.string.bytes != null) {
                break :blk src.body.string.bytes.?[0..src.body.string.byte_length :0];
            }
        } else if (src.head.bytes != null) {
            break :blk src.head.bytes.?[0..src.head.length :0];
        }
        break :blk null;
    };

    if (bytes_to_copy) |to_copy| {
        var new_string: ?[:0]u8 = null;
        errdefer if (new_string) |to_free| allocator.free(to_free);

        if (!dest.head.is_synthetic) {
            new_string = try allocator.dupeZ(u8, to_copy);
            dest.head.bytes = new_string.?.ptr;
            dest.head.length = @intCast(to_copy.len);
        } else if (src.head.tag == .string and dest.head.tag == .none) {
            // Copying into a synthetic head, so that means we'll
            // put the string in the body instead
            new_string = try allocator.dupeZ(u8, to_copy);
            dest.body.string.bytes = new_string.?.ptr;
            dest.body.string.byte_length = @intCast(to_copy.len);
            dest.body.string.utf8_length = src.body.string.utf8_length;
            dest.head.tag = .string;

            // String copying to a body means we've completed the needed
            // duplication.
            return;
        }
    }

    // Compact lists are a special case
    if (src.head.is_compact_list) {
        // Option 1: We're duplicating into a compact list
        if (dest.head.is_compact_list) {
            assert(dest.body.compact_list.capacity >= src.body.compact_list.length);

            var synthetic_head = Head{
                .ref_count = 1,
                .ref_counted = false,
                .mutable = false,
                .is_compact_list = false,
                .is_synthetic = true,
                .tag = src.head.tag,
            };

            // Duplicate the body from the old list to the new
            var i: usize = 0;
            while (i < src.body.compact_list.length) : (i += 1) {
                const src_body = &src.body.compact_list.elements[i];
                const dest_body = &dest.body.compact_list.elements[i];

                // Make sure bytes is initialized, so that if freeString is called (due
                // to an error), it doesn't try to free an uninitialized value
                dest_body.string.bytes = null;

                try duplicateOnto(
                    allocator,
                    .{ .head = &synthetic_head, .body = src_body },
                    .{ .head = &synthetic_head, .body = dest_body },
                );
            }
            errdefer {
                for (0..i) |j| {
                    const dest_body = &dest.body.compact_list.elements[j];

                    freeInternals(allocator, .{
                        .head = &synthetic_head,
                        .body = dest_body,
                    });
                }
            }

            dest.body.compact_list.length = src.body.compact_list.length;
            dest.head.tag = src.head.tag;
        } else {
            // Option 2: Not a compact list, so we'll need to box everything.
            var new_list = try allocator.alloc(Object, src.body.compact_list.length);
            errdefer allocator.free(new_list);

            var i: usize = 0;
            while (i < src.body.compact_list.length) : (i += 1) {
                // Make sure bytes is initialized, so that if freeString is called (due
                // to an error), it doesn't try to free an uninitialized value
                new_list[i].head.bytes = null;

                new_list[i] = init();
                var synthetic_head = Head{
                    .ref_count = 1,
                    .ref_counted = false,
                    .mutable = true,
                    .is_compact_list = false,
                    .is_synthetic = true,
                    .tag = .string,
                };
                try duplicateOnto(allocator, .{
                    .head = &synthetic_head,
                    .body = &src.body.compact_list.elements[i],
                }, new_list[i].asRef());
            }
            errdefer {
                for (0..i) |j| {
                    freeInternals(allocator, new_list[j].asRef());
                }
            }

            dest.head.tag = .list;
        }

        return;
    }

    switch (src.head.tag) {
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
                try duplicateOnto(allocator, hash_map.keys()[i].asRef(), new_hash_map.keys()[i].asRef());
                try duplicateOnto(allocator, hash_map.values()[i].asRef(), new_hash_map.values()[i].asRef());
            }
            errdefer {
                for (0..i) |j| {
                    freeInternals(allocator, new_hash_map.keys()[j].asRef());
                    freeInternals(allocator, new_hash_map.values()[j].asRef());
                }
            }

            dest.body.dictionary.hash_map = &new_hash_map;
        },
        .custom_type => {
            src.body.custom_type.type_ptr.duplicate(allocator, src, dest);
        },
        .string => {
            // Make sure to update bytes pointer to new object's bytes
            dest.body.string.bytes = dest.head.bytes;

            dest.body.string.byte_length = src.body.string.byte_length;
            dest.body.string.utf8_length = src.body.string.utf8_length;
        },
        .index, .return_code, .number, .float => {
            dest.body.* = src.body.*;
        },
        .none => {},
    }

    dest.head.tag = src.head.tag;
}

pub fn duplicate(allocator: Allocator, src: Ref) !Ref {
    const normal_size = @sizeOf(Object);
    var new_obj: *Object = undefined;

    if (src.head.is_compact_list) {
        const length = src.body.compact_list.length;
        const compact_list_size = @sizeOf(Body) * length;
        const bytes = try allocator.alignedAlloc(u8, std.mem.Alignment.of(Object), normal_size + compact_list_size);

        const new_list: [*]Body = @ptrCast(bytes.ptr + normal_size);
        new_obj = @ptrCast(bytes);

        new_obj.body.compact_list.elements = new_list;
        new_obj.body.compact_list.capacity = length;
        new_obj.body.compact_list.length = length;
    } else {
        const bytes = try allocator.alignedAlloc(u8, std.mem.Alignment.of(Object), normal_size);
        new_obj = @ptrCast(bytes);
    }

    new_obj.head = .{
        .ref_count = 1,
        .ref_counted = true,
        .mutable = true,
        .is_compact_list = src.head.is_compact_list,
        .is_synthetic = false,
    };

    try duplicateOnto(allocator, src, new_obj.asRef());
    return new_obj.asRef();
}

test "Object duplication" {
    const ta = std.testing.allocator;

    // Number object
    var obj = init();
    obj.head.tag = .number;
    obj.body.number = 10;

    const new_obj = try duplicate(ta, obj.asRef());
    defer release(ta, new_obj);

    try expectEqual(.number, new_obj.head.tag);
    try expectEqual(10, new_obj.body.number);

    // try borrowing
    const borrowed = try borrow(ta, new_obj, false);
    try expectEqual(borrowed, new_obj);
    try expectEqual(2, new_obj.head.ref_count);

    release(ta, borrowed);
    try expectEqual(1, new_obj.head.ref_count);
}

pub const ObjectListRef = union(enum) {
    normal: *Body.List,
    compact: struct {
        head: *Head,
        list: *Body.CompactList,
    },
    dictionary: *Body.HashMap,

    /// ObjectListRef must not move for the duration of this reference
    pub fn get(self: *ObjectListRef, index: usize) Ref {
        switch (self.*) {
            .normal => |list| {
                return list.elements[0..list.length][index].asRef();
            },
            .compact => |compact| {
                return .{
                    .head = compact.head,
                    .body = &compact.list.elements[0..compact.list.length][index],
                };
            },
            .dictionary => |dict| {
                if (@rem(index, 2) == 0) {
                    return dict.keys()[index / 2].asRef();
                } else {
                    return dict.values()[index / 2].asRef();
                }
            },
        }
    }

    pub fn length(self: *ObjectListRef) usize {
        switch (self.*) {
            .normal => |list| return list.length,
            .compact => |compact| return compact.list.length,
            .dictionary => |dict| return dict.count() * 2,
        }
    }
};

fn getListString(allocator: Allocator, list: *ObjectListRef) ![:0]u8 {
    const QuotingTypeAndString = struct {
        quoting_type: string_utils.QuotingType,
        string: [:0]u8,
    };

    // Keep all the quoting results on the stack, if possible. If not,
    // we'll make an allocation.
    var sub_strings: []QuotingTypeAndString = undefined;
    var sub_strings_on_stack: [32]QuotingTypeAndString = undefined;
    if (list.length() > sub_strings_on_stack.len) {
        sub_strings = try allocator.alloc(QuotingTypeAndString, list.length());
    } else {
        sub_strings = sub_strings_on_stack[0..list.length()];
    }
    defer if (sub_strings.ptr != sub_strings_on_stack[0..].ptr) {
        allocator.free(sub_strings);
    };

    var total_length: usize = 0;
    for (0..list.length()) |i| {
        // Calculate the string only once, because getString may transfer ownership
        // to us if this is a compact list
        const element_string = try getString(allocator, list.get(i));
        sub_strings[i] = .{
            .quoting_type = string_utils.calculateNeededQuotingType(element_string),
            .string = element_string,
        };
        if (i == 0 and sub_strings[i].quoting_type == .bare and
            element_string.len > 0 and element_string[0] == '#')
        {
            // Make sure the first element has # escaped in braces
            sub_strings[i].quoting_type = .brace;
        }
        total_length += string_utils.quoteSize(sub_strings[i].quoting_type, element_string.len);
        total_length += 1; // space between each element
    }

    var unfinished_str = try allocator.alloc(u8, total_length + 1);
    errdefer allocator.free(unfinished_str);
    var written: usize = 0;

    for (0..list.length()) |i| {
        const element_string = try getString(allocator, list.get(i));
        written += string_utils.quoteString(
            sub_strings[i].quoting_type,
            sub_strings[i].string,
            unfinished_str[written..],
            i == 0,
        );

        if (list.get(i).head.is_synthetic) {
            // This was a temporary string, so we need to free it
            allocator.free(element_string);
        }

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

/// For internal use only. If head.is_synthetic, this will
/// return a string that transfers ownership to the caller.
fn getString(allocator: Allocator, ref: Ref) Allocator.Error![:0]u8 {
    // Check if it already has a string representation
    if (ref.head.bytes) |bytes| {
        return bytes[0..ref.head.length :0];
    } else if (ref.head.tag == .string and ref.body.string.bytes != null) {
        return ref.body.string.bytes.?[0..ref.body.string.byte_length :0];
    }

    // No representation, so we better generate it
    var new_str: [:0]u8 = undefined;
    if (ref.head.is_compact_list) {
        var head = Head{
            .ref_count = 1,
            .ref_counted = false,
            .mutable = false,
            .is_compact_list = false,
            .is_synthetic = true,
            .tag = ref.head.tag,
        };
        var list = ObjectListRef{
            .compact = .{
                .head = &head,
                .list = &ref.body.compact_list,
            },
        };
        return getListString(allocator, &list);
    }

    switch (ref.head.tag) {
        .index => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{ref.body.index}, 0);
        },
        .return_code => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{ref.body.return_code}, 0);
        },
        .number => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{ref.body.number}, 0);
        },
        .float => {
            new_str = try std.fmt.allocPrintSentinel(allocator, "{}", .{ref.body.float}, 0);
        },
        .list => {
            var list = ObjectListRef{
                .normal = &ref.body.list,
            };
            new_str = try getListString(allocator, &list);
        },
        .dictionary => {
            var list = ObjectListRef{
                .dictionary = ref.body.dictionary.hash_map,
            };
            new_str = try getListString(allocator, &list);
        },
        .custom_type => {
            new_str = try ref.body.custom_type.type_ptr.get_string(allocator, ref);
        },
        .string, .none => {
            @panic("Tried to generate a string with no body");
        },
    }

    if (ref.head.is_synthetic) {
        // Caller is responsible for freeing in this case
        return new_str;
    } else {
        ref.head.bytes = new_str.ptr;
        ref.head.length = @truncate(new_str.len);
        return new_str;
    }
}

test "Get string" {
    const ta = std.testing.allocator;

    var obj = init();
    obj.head.tag = .number;
    obj.body.number = 10;
    defer freeInternals(ta, obj.asRef());

    try expectEqualSlices(u8, "10", try getString(ta, obj.asRef()));
}

/// Frees the string and body
pub fn freeInternals(alloc: Allocator, ref: Ref) void {
    freeString(alloc, ref);
    invalidateBody(alloc, ref);
}

/// This is slightly different than invalidateString, because invalidateString
/// won't free a compact list's string, while this will
pub fn freeString(allocator: Allocator, ref: Ref) void {
    if (ref.head.bytes) |bytes| {
        allocator.free(bytes[0..ref.head.length :0]);
        ref.head.bytes = null;
    } else if (ref.head.is_synthetic and ref.head.tag == .string) {
        // If we're a compact list's string, head.bytes will be null, but
        // body.string.bytes may hold a value
        if (ref.body.string.bytes) |bytes| {
            allocator.free(bytes[0..ref.body.string.byte_length]);
            ref.body.string.bytes = null;
        }
    }
}

pub fn invalidateString(allocator: Allocator, ref: Ref) void {
    if (ref.head.bytes) |bytes| {
        allocator.free(bytes[0..ref.head.length :0]);
        ref.head.bytes = null;
    }
}

/// Caller is responsible for syncing the body contents
/// across threads before calling.
pub fn invalidateBody(alloc: Allocator, ref: Ref) void {
    if (ref.head.tag == .none) return; // nothing to do

    // Special case: is it a compact list?
    if (ref.head.is_compact_list) {
        // Because the compact list is part of the allocation of
        // the object head, we don't actually free any of the objects.
        // Instead, we just make sure that their bodies' values are
        // released.

        var synthetic_head = Head{
            .bytes = null,
            .length = 0,
            .ref_count = 0,
            .tag = ref.head.tag,
            // Not relevant, as we're running a destructor
            .cross_thread = false,
            // Needs to be mutable to free
            .mutable = true,
            // Owned by the parent object, so not ref counted
            .ref_counted = false,
            // Compact lists cannot contain other compact lists
            .is_compact_list = false,
            .is_synthetic = true,
        };

        // Release each item's internals
        for (0..ref.body.compact_list.length) |i| {
            freeInternals(alloc, .{
                .head = &synthetic_head,
                .body = &ref.body.compact_list.elements[i],
            });
        }

        ref.body.compact_list.length = 0;
        ref.head.tag = .none;
        return;
    }

    switch (ref.head.tag) {
        .list => {
            const list = ref.body.list;

            for (0..list.length) |i| {
                freeInternals(alloc, list.elements[i].asRef());
            }

            alloc.free(list.elements[0..list.capacity]);
        },
        .dictionary => {
            const hash_map = ref.body.dictionary.hash_map;

            // Be sure to free the keys and values before freeing the container
            var iter = hash_map.iterator();
            while (iter.next()) |entry| {
                freeInternals(alloc, entry.key_ptr.asRef());
                freeInternals(alloc, entry.value_ptr.asRef());
            }

            hash_map.deinit(alloc);
        },
        .custom_type => {
            ref.body.custom_type.type_ptr.free_body(alloc, ref);
        },
        .string => {
            // How come string is a no-op? Because we could potentially
            // double-free when freeStringRep is called.
        },
        .none, .index, .return_code, .number, .float => {},
    }
}

/// Gets the size of an object
pub fn size(ref: Ref) usize {
    const normal_size = @sizeOf(Object);
    const compact_list_size =
        if (ref.head.is_compact_list) @sizeOf(Body) * ref.body.compact_list.length else 0;

    return normal_size + compact_list_size;
}

pub fn asRef(obj: *Object) Ref {
    return .{
        .head = &obj.head,
        .body = &obj.body,
    };
}

pub fn asConst(obj: *Object) ConstRef {
    return .{
        .head = &obj.head,
        .body = &obj.body,
    };
}
