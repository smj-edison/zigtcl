const std = @import("std");

pub const Node = struct {
    tag: Tag,

    pub const Tag = enum {
        // Binary operators
        mul,
        div,
        mod,
        sub,
        add,
        shiftl,
        shiftr,
        rotl,
        rotr,
        less_than,
        greater_than,
        less_or_equal,
        greater_or_equal,
        equal_equal,
        bang_equal,
        bit_and,
        bit_xor,
        bit_or,
        logic_and,
        logic_or,
        ternary,
        colon,
        pow,
        // Unary operators
        bool_not,
        bit_not,
        unary_plus,
        unary_minus,
        // Builtin functions
        int,
        wide,
        abs,
        double,
        round,
        rand,
    };
};
