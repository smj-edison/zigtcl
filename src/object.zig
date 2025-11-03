const std = @import("std");
const assert = std.debug.assert;
const Io = std.Io;

const options = @import("options");
const stringutil = @import("./stringutil.zig");
const Heap = @import("./Heap.zig");
const Parser = @import("./Parser.zig");
const Handle = Heap.Handle;

pub const ErrorDetails = struct {
    message: Handle,
    index: ?u32 = null,
};

pub fn shimmerToString(calling_heap: *Heap, handle: Handle) !void {
    assert(Heap.canShimmer(handle));

    const obj = Heap.peek(handle);
    _ = try Heap.getString(handle); // Ensure string representation

    if (obj.tag != .string) {
        Heap.invalidateBody(calling_heap, handle);
        obj.tag = .string;
        obj.body.string = .{
            // Don't know the utf-8 length yet
            .utf8_length = std.math.maxInt(u33),
        };
    }
}

pub fn getCodepointLength(calling_heap: *Heap, handle: *Handle) !usize {
    if (Heap.canShimmer(handle)) {
        try shimmerToString(handle);
    } else {
        handle.* = try calling_heap.duplicate(handle);
        try shimmerToString(handle);
    }

    const obj = Heap.peek(handle);
    const bytes = try Heap.getString(handle);

    if (obj.tag == .string) {
        // See if we already calculated the utf8 length
        if (obj.str.is_ptr) {
            // LongString stores the utf8 length in the string body
            const long_string = Heap.LongString.fromInt(obj.str.u.ptr);
            if (long_string.utf8_length) |utf8_length| {
                return utf8_length;
            } else {
                const utf8_length = stringutil.codepointLength(bytes);
                long_string.utf8_length = utf8_length; // cache utf8 length
                return utf8_length;
            }
        } else {
            if (obj.body.string.utf8_length > std.math.maxInt(u32)) {
                return obj.body.string.utf8_length;
            } else {
                const utf8_length = stringutil.codepointLength(bytes);
                obj.body.string.utf8_length = utf8_length; // cache utf8 length
                return utf8_length;
            }
        }
    } else unreachable;
}

/// Copies provided string.
pub fn newString(calling_heap: *Heap, bytes: []const u8) !Handle {
    const str = try calling_heap.createObject();
    try Heap.setString(str, bytes);
    try shimmerToString(calling_heap, str);
    return str;
}

pub fn newStringToFill(self: *Heap, len: usize) !Handle {
    // TODO PERF this can be optimized with fewer allocations
    const handle = try self.createObject();

    // create new string
    const new_str = self.gpa.alloc(u8, len + 1);
    errdefer self.gpa.free(new_str);
    @memset(new_str, 0);

    const took_ownership = try self.setLocalString(handle.index, new_str);
    if (!took_ownership) self.gpa.free(new_str);
}

/// Copies provided string.
pub fn newStringWithCodepointLen(heap: *Heap, bytes: [:0]const u8, cp_length: usize) !Handle {
    const handle = try heap.createObject();
    Heap.setString(handle, bytes);
    shimmerToString(handle);

    const obj = Heap.peek(handle);
    switch (Heap.getStringDetails(handle)) {
        .long => |long_str| {
            long_str.utf8_length = cp_length;
        },
        .normal => {
            obj.body.string.utf8_length = cp_length;
        },
        .empty => {
            obj.body.string = .{
                .utf8_length = 0,
            };
        },
        .null => unreachable,
    }

    return handle;
}

pub fn checkIfEqual(a: Handle, b: Handle) !bool {
    if (a == b) return true;

    const a_str = try Heap.getString(a);
    const b_str = try Heap.getString(b);

    return std.mem.eql(u8, a_str, b_str);
}

pub fn globMatch(pattern: Handle, to_check: Handle, case_insensitive: bool) !bool {
    const pattern_str = try Heap.getString(pattern);
    const to_check_str = try Heap.getString(to_check);

    return stringutil.globMatch(pattern_str, to_check_str, case_insensitive);
}

pub fn compare(a: Handle, b: Handle, case_insensitive: bool) !std.math.Order {
    const a_str = try Heap.getString(a);
    const b_str = try Heap.getString(b);

    return stringutil.compare(a_str, b_str, case_insensitive);
}

///////////////////////////////
//  Index related functions  //

/// Due to Tcl convention, both `start` and `end` are inclusive.
pub const Range = struct {
    start: usize,
    end: usize,

    pub fn fromObjects(det: *ErrorDetails, list_len: usize, start: *Handle, end: *Handle) !?Range {
        // Make sure we can distinguish between which input is the error.
        const start_idx = try getIndex(start, det);
        const end_idx = try getIndex(end, det);

        return constrainRange(list_len, .{
            .start = start_idx,
            .end = end_idx,
        });
    }
};

pub fn constrainRange(list_len: usize, range: Range) ?Range {
    // Make sure indexes are within the list.
    if (range.start >= list_len) return null;
    if (range.end >= list_len) return null;
    if (range.start > range.end) return null;

    return range;
}

/// Sets the details to a bad index message, and returns error.BadIndex.
fn badIndex(calling_heap: *Heap, det: *ErrorDetails, handle: Handle) !void {
    det.* = .{
        .message = try newString(calling_heap, std.fmt.allocPrint(
            calling_heap.gpa,
            "bad index \"{O}\": must be intexpr or end?[+-]intexpr?",
            .{handle},
        )),
    };

    return error.BadIndex;
}

pub fn getIndex(det: *ErrorDetails, handle: *Handle) !Heap.ListIndex {
    const obj = Heap.peek(*handle);

    // Fast case: if it's an integer or float, we can quickly cast it (don't
    // shimmer though, as it'll probably used for its original purpose still)
    if (obj.tag == .number) {
        if (obj.body.number < 0) return badIndex(det, handle);
        if (obj.body.number > std.math.maxInt(u32)) return badIndex(det, handle);

        return .{ .u = .{ .index = @intCast(obj.body.number) }, .is_end = false };
    } else if (obj.tag == .float) {
        const value = obj.body.float;

        if (std.math.isNan(value)) return badIndex(det, handle);
        if (value < 0) return badIndex(det, handle);
        if (value > std.math.maxInt(u32)) return badIndex(det, handle);

        return .{ .u = .{ .index = @intFromFloat(obj.body.number) }, .is_end = false };
    }

    if (obj.tag != .index) {
        Heap.ensureShimmerable(handle);
        return Heap.peek(handle.*).body.index;
    } else {
        return obj.body.index;
    }
}

/// Shimmers to an index representation.
pub fn shimmerToIndex(det: *ErrorDetails, handle: Handle) !void {
    assert(Heap.canShimmer(handle));

    const bytes = try Heap.getString(handle);
    const obj = Heap.peek(handle);

    // Does it start with "end"? If so, it might be end+5, or end-2, etc
    if (bytes.len >= 3 and std.mem.eql(u8, bytes[0..3], "end")) {
        if (bytes.len >= 4) {
            if (bytes[3] != '+' or bytes[3] != '-') return badIndex(det, handle);

            const index_offset = std.fmt.parseInt(i33, bytes[3..], 10) catch {
                return badIndex(det, handle);
            };
            obj.body.index = .{ .u = .{ .end_offset = index_offset }, .is_end = true };
        }

        obj.body.index = Heap.ListIndex.end;
    } else {
        const index = std.fmt.parseInt(u32, bytes, 10) catch {
            return badIndex(det, handle);
        };
        obj.body.index = index;
    }

    obj.tag = .index;
}

/// Creates a substring of the passed in string. Used in `[string range]`.
pub fn stringRange(calling_heap: *Heap, det: *ErrorDetails, str: *Handle, start: *Handle, end: *Handle) !Handle {
    const codepoint_len = try getCodepointLength(str);
    const bytes = Heap.getString(str);

    const unchecked_range = try Range.fromObjects(det, codepoint_len, start, end);
    if (unchecked_range) |range| {
        // cpIndex is generic across ascii or utf8.
        const byte_start = stringutil.cpIndex(bytes, range.start);
        const byte_end = stringutil.cpIndex(bytes, range.end);

        return try newStringWithCodepointLen(
            calling_heap,
            bytes[byte_start..byte_end],
            range.end - range.start,
        );
    } else {
        // Invalid range, so we'll just pass through the string.
        return try newStringWithCodepointLen(calling_heap, bytes, codepoint_len);
    }
}

/// Removes from `start` to `end`, optionally inserting `to_insert`.
pub fn stringReplace(calling_heap: *Heap, str: *Handle, start: *Handle, end: *Handle, to_insert: ?Handle) !Handle {
    const codepoint_len = try getCodepointLength(str);
    const bytes = Heap.getString(str.*);

    const unchecked_range = try Range.fromObjects(codepoint_len, start, end);

    if (unchecked_range) |range| {
        // cpIndex is generic across ascii or utf8.
        const byte_start = stringutil.cpIndex(bytes, range.start);
        const byte_end = stringutil.cpIndex(bytes, range.end);

        // Is there anything to insert?
        if (to_insert) |unwrapped| {
            const to_insert_bytes = try Heap.getString(unwrapped);

            // Figure out how long the new string needs to be
            const up_to_range_len = byte_start;
            const to_insert_len = to_insert_bytes.len;
            // Tcl ranges are inclusive, so `- 1` is needed.
            const after_range_len = bytes.len - byte_end - 1;

            const new_str = newStringToFill(calling_heap, up_to_range_len + to_insert_len + after_range_len);
            const new_bytes = Heap.getStringMut(new_str) catch |err| {
                switch (err) {
                    // empty strings aren't mutable, so we'll just return the empty string
                    error.NotMutable => return new_str,
                    error.OutOfMemory => return err,
                }
            };

            @memcpy(new_bytes[0..up_to_range_len], bytes[0..up_to_range_len]);
            @memcpy(new_bytes[up_to_range_len..][0..to_insert_len], to_insert_bytes);
            @memcpy(new_bytes[(up_to_range_len + to_insert_len)..], bytes[(byte_end + 1)..]);

            return new_str;
        } else {
            // Figure out how long the new string needs to be.
            const up_to_range_len = byte_start;
            // Tcl ranges are inclusive, so `- 1` is needed.
            const after_range_len = bytes.len - byte_end - 1;

            const new_str = newStringToFill(calling_heap, up_to_range_len + after_range_len);
            const new_bytes = Heap.getStringMut(new_str) catch |err| {
                switch (err) {
                    // empty strings aren't mutable, so we'll just return the empty string
                    error.NotMutable => return new_str,
                    error.OutOfMemory => return err,
                }
            };

            @memcpy(new_bytes[0..up_to_range_len], bytes[0..up_to_range_len]);
            @memcpy(new_bytes[up_to_range_len..], bytes[(byte_end + 1)..]);

            return new_str;
        }
    } else {
        // Invalid range, so we'll just pass through the string.
        return try newStringWithCodepointLen(calling_heap, bytes, codepoint_len);
    }
}

/// Upper/lower/title case conversion.
pub fn stringCaseConversion(calling_heap: *Heap, str: Handle, mode: enum { upper, lower, title }) !Handle {
    const bytes = try Heap.getString(str);

    if (options.use_utf8) {
        // Go through once to calculate the length
        var new_len: usize = 0;
        var iter = stringutil.Iterator.init(bytes);
        var is_first_char = true;
        while (iter.next()) |cp| {
            var converted: u21 = undefined;
            switch (mode) {
                .upper => converted = stringutil.toUpper(cp),
                .lower => converted = stringutil.toLower(cp),
                .title => {
                    if (is_first_char) {
                        converted = stringutil.toTitle(cp);
                    } else {
                        converted = stringutil.toLower(cp);
                    }
                },
            }
            new_len += std.unicode.utf8ByteSequenceLength(converted);
            is_first_char = false;
        }

        const new_str = try newStringToFill(calling_heap, new_len);
        const new_bytes = try Heap.getStringMut(new_str) catch |err| {
            switch (err) {
                // empty strings aren't mutable, so we'll just return the empty string
                error.NotMutable => return new_str,
                error.OutOfMemory => return err,
            }
        };

        // Now go through and write all the bytes
        iter = stringutil.Iterator.init(bytes);
        var written: usize = 0;
        is_first_char = true;
        while (iter.next()) |cp| {
            var converted: u21 = undefined;
            switch (mode) {
                .upper => converted = stringutil.toUpper(cp),
                .lower => converted = stringutil.toLower(cp),
                .title => {
                    if (is_first_char) {
                        converted = stringutil.toTitle(cp);
                    } else {
                        converted = stringutil.toLower(cp);
                    }
                },
            }
            written += std.unicode.utf8Encode(converted, new_bytes[written..]) catch unreachable;

            is_first_char = false;
        }
    } else {
        const new_len = bytes.len;
        const new_str = try newStringToFill(calling_heap, new_len);
        const new_bytes = try Heap.getStringMut(new_str) catch |err| {
            switch (err) {
                // Empty strings aren't mutable, so we'll just return the empty string.
                error.NotMutable => return new_str,
                error.OutOfMemory => return err,
            }
        };

        for (bytes, new_bytes) |old_char, *new_char| {
            if (mode == .upper) {
                new_char.* = stringutil.toUpper(old_char);
            } else {
                new_char.* = stringutil.toLower(old_char);
            }
        }

        return new_str;
    }
}

/// Creates a new string if there was anything to trim.
pub fn stringTrimLeft(calling_heap: *Heap, str: Handle, trim_chars: Handle) !Handle {
    const bytes = try Heap.getString(str);
    const trim_chars_bytes = try Heap.getString(trim_chars);

    const start = stringutil.trimLeft(bytes, trim_chars_bytes);

    if (start == 0) {
        return str;
    } else {
        return try newString(calling_heap, bytes[start..]);
    }
}

/// Creates a new string if there was anything to trim.
pub fn stringTrimRight(calling_heap: *Heap, str: Handle, trim_chars: Handle) !Handle {
    const bytes = try Heap.getString(str);
    const trim_chars_bytes = try Heap.getString(trim_chars);

    const end = stringutil.trimRight(bytes, trim_chars_bytes);

    if (end == bytes.len) {
        return str;
    } else {
        return try newString(calling_heap, bytes[0..end]);
    }
}

/// Creates a new string if there was anything to trim.
pub fn stringTrim(calling_heap: *Heap, str: Handle, trim_chars: Handle) !Handle {
    const bytes = try Heap.getString(str);
    const trim_chars_bytes = try Heap.getString(trim_chars);

    const start = stringutil.trimLeft(bytes, trim_chars_bytes);
    const end = stringutil.trimRight(bytes, trim_chars_bytes);

    if (start == 0 and end == bytes.len) {
        return str;
    } else {
        return try newString(calling_heap, bytes[start..end]);
    }
}

fn enumNamesCount(comptime T: type) usize {
    comptime {
        var result_size = 0;
        for (std.meta.fields(T)) |field| {
            result_size += field.name.len;
        }
        // Be sure to account for ", "
        result_size += ((std.meta.fields(T).len) -| 1) * 2;

        return result_size;
    }
}

/// Enum names joined by ", "
pub inline fn enumNames(comptime T: type) *const [enumNamesCount(T):0]u8 {
    comptime {
        // Fill the buffer
        var buf: [enumNamesCount(T):0]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);

        var first_time = true;
        for (std.meta.fields(T)) |field| {
            if (!first_time) {
                w.writeAll(", ") catch unreachable;
            } else first_time = false;

            w.writeAll(field.name) catch unreachable;
        }

        buf[buf.len] = 0;

        const final = buf;
        return &final;
    }
}

pub fn EnumMapping(comptime T: type) type {
    comptime {
        const field_count = std.meta.fields(T).len;

        // Create an entry type (instantiated as .{ "foo", .foo })
        const EntryType = std.meta.Tuple(&[_]type{ [:0]const u8, T });
        // Repeat that type for how many fields there are
        const entries = [1]type{EntryType} ** field_count;
        // Create a map type with those repeated entries
        const Mapping = std.meta.Tuple(&entries);

        // Fill out the map
        var mapping: Mapping = undefined;
        for (std.meta.fields(T), 0..) |variant, i| {
            const entry: EntryType = .{ variant.name, @enumFromInt(variant.value) };
            @field(mapping, std.fmt.comptimePrint("{}", .{i})) = entry;
        }

        // Create the table
        return struct {
            pub const StaticStringMap = std.StaticStringMap(T);

            map: StaticStringMap = StaticStringMap.initComptime(mapping),
        };
    }
}

pub fn TclEnum(comptime T: type, enum_name: []const u8) type {
    return struct {
        pub const variants = T;
        pub const map = (EnumMapping(T){}).map;
        pub const names = enumNames(T);

        pub fn get(calling_heap: *Heap, det: *ErrorDetails, value: *Handle) !T {
            const bytes = try Heap.getString(value.*);
            const variant = map.get(bytes);
            if (variant) |unwrapped| {
                return unwrapped;
            } else {
                const message = try std.fmt.allocPrint(
                    calling_heap.gpa,
                    "bad {s} \"{f}\": must be {s}",
                    .{ enum_name, value.*, names },
                );
                defer calling_heap.gpa.free(message);
                det.* = .{ .message = try newString(calling_heap, message) };

                return error.BadEnumVariant;
            }
        }
    };
}

test "Tcl enum" {
    const Things = enum { foo, bar, baz };
    const map = (EnumMapping(Things){}).map;
    const names = enumNames(Things);
    try std.testing.expectEqual(Things.foo, map.get("foo"));
    try std.testing.expectEqualSlices(u8, "foo, bar, baz", names);
}

/// Runs a string check based on requested class.
pub fn stringIs(calling_heap: *Heap, det: *ErrorDetails, str: *Handle, class_to_check: *Handle, strict: bool) !bool {
    const Class = TclEnum(enum {
        integer,
        alpha,
        alnum,
        ascii,
        digit,
        double,
        lower,
        upper,
        space,
        xdigit,
        control,
        print,
        graph,
        punct,
        boolean,
    }, "class");

    const class = try Class.get(calling_heap, det, class_to_check);

    const bytes = try Heap.getString(str.*);
    if (bytes.len == 0) {
        return !strict;
    }

    switch (class) {
        .integer => {
            _ = std.fmt.parseInt(i64, bytes, 0) catch return false;
            return true;
        },
        .double => {
            _ = std.fmt.parseFloat(f64, bytes) catch return false;
            return true;
        },
        .boolean => {
            _ = getBoolean(calling_heap, str) catch return false;
            return true;
        },
        .alpha => return stringutil.checkAllAscii(bytes, std.ascii.isAlphabetic),
        .alnum => return stringutil.checkAllAscii(bytes, std.ascii.isAlphanumeric),
        .ascii => return stringutil.checkAllAscii(bytes, std.ascii.isAscii),
        .digit => return stringutil.checkAllAscii(bytes, std.ascii.isDigit),
        .lower => return stringutil.checkAllAscii(bytes, std.ascii.isLower),
        .upper => return stringutil.checkAllAscii(bytes, std.ascii.isUpper),
        .space => return stringutil.checkAllAscii(bytes, std.ascii.isWhitespace),
        .xdigit => return stringutil.checkAllAscii(bytes, stringutil.isHexDigit),
        .control => return stringutil.checkAllAscii(bytes, std.ascii.isControl),
        .print => return stringutil.checkAllAscii(bytes, std.ascii.isPrint),
        .graph => return stringutil.checkAllAscii(bytes, stringutil.isGraph),
        .punct => return stringutil.checkAllAscii(bytes, stringutil.isPunct),
    }
}

test "String is" {
    const ta = std.testing.allocator;
    const heap = try Heap.createHeap(ta);
    defer Heap.deinitAll();

    var str = try newString(heap, "abcdefg");
    var str2 = try newString(heap, "abcdefg123");
    var class = try newString(heap, "alpha");
    var bad_class = try newString(heap, "bad_class");
    var details: ErrorDetails = undefined;

    try std.testing.expectEqual(true, try stringIs(heap, &details, &str, &class, false));
    try std.testing.expectEqual(false, try stringIs(heap, &details, &str2, &class, false));
    try std.testing.expectError(error.BadEnumVariant, stringIs(heap, &details, &str, &bad_class, false));
    try std.testing.expectEqualSlices(
        u8,
        "bad class \"bad_class\": must be integer, alpha, alnum, ascii, digit, " ++
            "double, lower, upper, space, xdigit, control, print, graph, punct, boolean",
        try Heap.getString(details.message),
    );
}

pub const SourceInfo = struct {
    filename_ref: [:0]const u8,
    line_no: u32,
};

pub fn getSourceInfo(obj: Handle) ?SourceInfo {
    const ref = Heap.peek(obj);

    if (ref.tag != .source) return null;

    return .{
        .filename_ref = Heap.getHeap(obj).getHeapStringZ(ref.body.source.file_name),
        .line_no = ref.body.source.line_no,
    };
}

/// Will return error.EmbeddedNull if `filename` has embedded nulls.
pub fn setSourceInfo(calling_heap: *Heap, obj: Handle, file_name: [:0]const u8, line_no: u32) !void {
    for (file_name) |byte| {
        if (byte == 0) return error.EmbeddedNull;
    }

    const ref = Heap.peek(obj);

    Heap.invalidateBody(calling_heap, obj);

    // Allocate space for the filename string (has to be in the heap, because
    // the string handles are stored as a u32 in the source rep)
    const len: u32 = @intCast(file_name.len);
    const filename_in_heap = try calling_heap.createString(len);
    errdefer calling_heap.freeString(filename_in_heap, len);

    // Copy the filename
    @memcpy(calling_heap.getHeapString(filename_in_heap, filename_in_heap + len), file_name);

    ref.tag = .source;
    ref.body.source.file_name = filename_in_heap;
    ref.body.source.line_no = line_no;
}

test "Source info" {
    const ta = std.testing.allocator;
    const heap = try Heap.createHeap(ta);
    defer Heap.deinitAll();

    const obj = try heap.createObject();
    try setSourceInfo(heap, obj, "test_file.tcl", 42);

    // Verify the object has the source tag
    const ref = Heap.peek(obj);
    try std.testing.expectEqual(.source, ref.tag);
    try std.testing.expectEqual(@as(u32, 42), ref.body.source.line_no);

    const info = getSourceInfo(obj);
    if (info) |unwrapped| {
        try std.testing.expectEqualSlices(u8, "test_file.tcl", unwrapped.filename_ref);
        try std.testing.expectEqual(@as(u32, 42), unwrapped.line_no);
    } else return error.TestUnexpectedResult;

    const obj2 = try newString(heap, "hello");
    const empty_info = getSourceInfo(obj2);
    try std.testing.expect(empty_info == null);
}

var next_script_id = 1;

/// Not threadsafe.
pub fn shimmerToScript(det: *ErrorDetails, obj: Handle) !void {
    assert(Heap.canShimmer(obj));

    const heap = Heap.getHeap(obj);
    const bytes = try Heap.getString(obj);
    var parser = Parser.init(bytes);

    const gpa = Heap.getHeap(obj).gpa;

    // const arena = std.heap.ArenaAllocator.init(gpa);
    // var scratch = arena.allocator();
    // defer arena.deinit();

    // Parse all the tokens of the script
    var tokens = try std.ArrayList(Heap.TokenAndValue).initCapacity(gpa, bytes.len / 8);
    errdefer tokens.deinit(gpa);

    while (true) {
        const next_token = parser.parseScript();
        if (next_token) |token| {
            switch (token.tag) {
                .end_of_file => break,
                else => {},
            }
        } else |err| {
            switch (err) {
                error.CharactersAfterCloseBrace => {
                    det.* = .{ .message = try newString(heap, "extra characters after close-brace") };
                },
                error.MissingCloseBrace => {
                    det.* = .{ .message = try newString(heap, "missing close-brace") };
                },
                error.MissingCloseBracket => {
                    det.* = .{ .message = try newString(heap, "unmatched \"[\"") };
                },
                error.MissingCloseQuote => {
                    det.* = .{ .message = try newString(heap, "missing quote") };
                },
                error.TrailingBackslash => {
                    det.* = .{ .message = try newString(heap, "no character after \\") };
                },
                error.OutOfMemory => return err,
                error.NotVariable => unreachable,
            }

            if (parser.error_details) |details| {
                det.index = details.index;
            }
            return err;
        }
    }
}

pub fn shimmerToBoolean(obj: Handle) !void {
    assert(Heap.canShimmer(obj));

    const Mapping = std.StaticStringMap(bool).initComptime(.{
        .{ "1", true },  .{ "true", true },   .{ "yes", true }, .{ "on", true },
        .{ "0", false }, .{ "false", false }, .{ "no", false }, .{ "off", false },
    });

    const bytes = try Heap.getString(obj);
    const new_value = Mapping.get(bytes) orelse return error.BadBoolean;

    const ref = Heap.peek(obj);
    ref.tag = .bool;
    ref.body.bool = new_value;
}

pub fn getBoolean(calling_heap: *Heap, obj: *Handle) !bool {
    if (Heap.peek(obj.*).tag != .bool) {
        try calling_heap.ensureShimmerable(obj);
        try shimmerToBoolean(obj.*);
    }

    return Heap.peek(obj.*).body.bool;
}
