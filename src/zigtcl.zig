const std = @import("std");
const string_utils = @import("string_utils.zig");

const empty_string = "";

const TclParser = struct {
    // Results of missing quotes, braces, etc. from parsing.
    const ParseMissing = struct {
        ch: u8, // At end of parse, ' ' if complete or '{', '[', '"', '\\', '}' if incomplete
        int: usize, // Line number starting the missing token
    };

    const TokenType = enum {
        none, // No token required
        string, // Simple string
        escaped_string, // String that needs escape chars conversion
        variable, // Variable substitution
        dict_sugar, // Syntax sugar for [dict get], $foo(bar)
        command, // command substitution
        separator, // word separator (white space)
        end_of_line, // line separator
        end_of_file, // end of script
        start_of_line, // special 'start-of-line' token. arg is # of arguments to the command. -ve if {*}
        start_of_word, // special 'start-of-word' token. arg is # of tokens to combine. -ve if {*}
    };

    const ParserCtx = struct {
        program: []const u8, // Program we are currently parsing.
        idx: u32 = 0, // program byte index
        line_no: u32, // current line number
        token: ?[]const u8 = null,
        token_line: u32 = 0, // Line number of the returned token

    };

    const Iterator = struct {};
};
