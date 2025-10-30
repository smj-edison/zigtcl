const std = @import("std");
const Type = std.builtin.Type;

pub fn EnumMapping(comptime Enum: type) type {
    comptime {
        const field_count = std.meta.fields(Enum).len;

        // Create an entry type (instantiated as .{ "foo", .foo })
        const EntryType = std.meta.Tuple(&[_]type{ [:0]const u8, Enum });
        // Repeat that type for how many fields there are
        const entries = [1]type{EntryType} ** field_count;
        // Create a map type with those repeated entries
        const Mapping = std.meta.Tuple(&entries);

        // Fill out the map
        var mapping: Mapping = undefined;
        for (std.meta.fields(Enum), 0..) |variant, i| {
            const entry: EntryType = .{ variant.name, @enumFromInt(variant.value) };
            @field(mapping, std.fmt.comptimePrint("{}", .{i})) = entry;
        }

        // Create the table
        return struct {
            pub const StaticStringMap = std.StaticStringMap(Enum);

            map: StaticStringMap = StaticStringMap.initComptime(mapping),
        };
    }
}

test {
    const Things = enum { foo, bar, baz };
    const map = (EnumMapping(Things){}).map;
    try std.testing.expectEqual(Things.foo, map.get("foo"));
}
