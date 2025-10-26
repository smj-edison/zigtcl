const std = @import("std");

// NOTE this is a rough sketch
// NOTE there are a bunch of things I don't know
// NOTE so take it with a grain of salt

pub const Kind = packed struct {
    pub const Flags = packed struct {
        /// Whether this object can be ref counted (else it needs to be cloned)
        ref_counted: bool,
        /// If shared across threads
        cross_thread: bool = false,
        /// Whether the body can be mutated (else it needs to be cloned)
        mutable: bool,

        pub const local_immutable: Flags = .{ .ref_counted = false, .mutable = false };
    };
    pub const Tag = enum(u5) { // NOTE only u4 needed
        none,
        index,

        // NOTE if return_code is really just a bool its tag could be packed together with
        // none something like code: enum {none, return_true, return_false} with three
        // interned instances in the handles array
        //
        // that would save one value for this enum, allowing it to fit in a u3
        // making the Tag smaller could allow for more Flags or alternatively we
        // could pack the .kind and the .index in the Handle together into a single u32
        //
        // u3 tag + u29 index
        // then Interpreter becomes a FlagGroup (Data that shares the same flags)
        // and you can create 8 of them for all the permutations of the 3 flags
        return_code,
        number,
        float,
        // string,
        // dictionary,
        // /// Non-compact list
        // list,
        // custom_type,
    };
    flags: Flags,
    tag: Tag,

    pub fn li(tag: Tag) Kind {
        return .{ .flags = .local_immutable, .tag = tag };
    }
};

pub const Object = struct {
    pub const Body = packed union {
        nothing: void,

        /// Array index
        index: u32,
        return_code: bool,
        number: i64,
        float: f64,
        // string: packed struct {
        //     /// bytes should always equal Head.bytes (why deduplicate? in case
        //     /// there's a compact list of strings--the Head is not stored)
        //     bytes: ?[*:0]u8,
        //     byte_length: u32,
        //     /// If = maxInt(u32), it means the length has not been determined
        //     utf8_length: u32,
        // },
        // list: List,
        /// Compact list stores only the body
        compact_list: CompactList,
        // dictionary: packed struct {
        //     /// Every object must have a pregenerated string representation in the hash map
        //     hash_map: *HashMap,
        // },
        // custom_type: packed struct {
        //     type_ptr: *anyopaque,
        //     value: *anyopaque,
        // },

        const List = packed struct {
            elements: [*]Handle, // NOTE also could potentially be an offset
            capacity: u32,
            length: u32,
        };
        const CompactList = packed struct {
            elements: [*]Handle.Index,
            capacity: u32,
            length: u32,
        };

        pub const HashMap = std.ArrayHashMapUnmanaged(Handle, Handle, Handle.HashContext, true);
    };

    kind: Kind,
    body: Body,
};

pub const Handle = struct {
    pub const Index = enum(u32) { _ };

    kind: Kind,

    /// NOTE if kind == .index  stores directly the target index
    /// NOTE if kind == .return_code  stores directly the return_code
    /// NOTE otherwise it is an index into a type specific array
    index: u32,

    pub const HashContext = struct {
        i: *Interpreter,

        pub fn hash(self: HashContext, obj: Handle) u32 {
            var hasher = std.hash.Wyhash.init(0);
            std.hash.autoHash(&hasher, obj.kind);
            switch (obj.kind) {
                .none => {},
                .index, .return_code => std.hash.autoHash(&hasher, obj.index),
                .number => std.hash.autoHash(&hasher, self.i.numbers.items[obj.index]),
                .floats => std.hash.autoHash(&hasher, self.i.floats.items[obj.index]),
            }
            return hasher.final();
        }

        pub fn eql(self: HashContext, lhs: Handle, rhs: Handle) bool {
            if (lhs.kind != rhs.kind) return false;

            return switch (lhs.kind) {
                .none => true,
                .index, .return_code => lhs.index == rhs.index,
                .number => self.i.numbers.items[lhs.index] == self.i.numbers.items[rhs.index],
                .floats => self.i.numbers.items[lhs.index] == self.i.numbers.items[rhs.index],
            };
        }
    };
};

const Interpreter = struct {
    const Handles = std.MultiArrayList(Handle);

    allocator: std.mem.Allocator,
    handles: Handles,

    numbers: std.ArrayList(i64),
    floats: std.ArrayList(f64),
    // ... more type specific arrays

    pub fn init(allocator: std.mem.Allocator) Interpreter {
        return .{
            .allocator = allocator,
            .handles = .empty,

            .numbers = .empty,
            .floats = .empty,
        };
    }

    const interned = [_]Handle{
        .{ .kind = .li(.return_code), .index = 0 },
        .{ .kind = .li(.return_code), .index = 1 },
        .{ .kind = .li(.none), .index = 2 },
    };
    /// creates interned instances
    pub fn setup(self: *Interpreter) !void {
        for (interned) |i| {
            try self.handles.append(self.allocator, i);
        }
    }

    pub fn deinit(self: *Interpreter) void {
        self.handles.deinit(self.allocator);
        self.numbers.deinit(self.allocator);
        self.floats.deinit(self.allocator);
    }

    pub fn add(self: *Interpreter, object: Object) !Handle.Index {
        try self.handles.ensureUnusedCapacity(self.allocator, 1);
        const new: Handle.Index = @enumFromInt(self.handles.len);
        const index: u32 = res: switch (object.kind.tag) {
            // NOTE if none is not mutable we can instead return the index
            // to the one constant interned instance which has a hardcoded index
            .return_code => return if (object.body.return_code) @enumFromInt(0) else @enumFromInt(1),
            .none => return @enumFromInt(2),
            .index => object.body.index,
            .number => {
                const i: u32 = @intCast(self.numbers.items.len);
                try self.numbers.append(self.allocator, object.body.number);
                break :res i;
            },
            .float => {
                const i: u32 = @intCast(self.floats.items.len);
                try self.floats.append(self.allocator, object.body.float);
                break :res i;
            },
        };
        self.handles.appendAssumeCapacity(.{
            .kind = object.kind,
            .index = index,
        });
        return new;
    }
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var interpreter: Interpreter = .init(allocator);
    defer interpreter.deinit();
    try interpreter.setup();

    _ = try interpreter.add(.{ .kind = .li(.none), .body = .{ .nothing = {} } });
    _ = try interpreter.add(.{ .kind = .li(.index), .body = .{ .index = 5 } });
    _ = try interpreter.add(.{ .kind = .li(.float), .body = .{ .float = 1244.5 } });
}
