// this design is very much inspired by Zig's tokenizer

const std = @import("std");
const string = @import("string_utils.zig");

const Token = struct {
    tag: Tag,
    loc: Location,

    pub const Location = struct {
        start: usize,
        end: usize,
        line_no: usize,
    };

    pub const Tag = enum {
        bare_string, // Simple string
        escaped_string, // String that needs escape character conversion
        quoted_string, // String in quotes (includes quotes)
        escaped_quoted_string, // String that is both in quotes and has escape characters
        argument_expansion, // Argument expansion (e.g. {*})
        variable_subst, // Variable substitution
        dict_sugar, // Syntax sugar for [dict get], $foo(bar)
        command_subst, // command substitution
        word_separator, // word separator (white space)
        command_separator, // command separator (line feed or semicolon)
        end_of_file, // end of script

        pub fn symbol(tag: Tag) []const u8 {
            return switch (tag) {
                .string => "string",
                .escaped_string => "escaped string",
                .variable_subst => "variable substitution",
                .dict_sugar => "dictionary sugar",
                .command_subst => "command substitution",
                .word_separator => "word separator",
                .command_separator => "command separator",
                .end_of_file => "end of file",
            };
        }
    };
};

const Tokenizer = struct {
    buffer: [:0]const u8,
    index: usize,
    line_no: u32, // current line number
    invalid_details: ParserError,

    pub fn init(buffer: [:0]const u8) Tokenizer {
        // Skip the UTF-8 BOM if present.
        return .{
            .buffer = buffer,
            .index = if (std.mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0,
            .line_no = 0,
            .invalid_details = null,
        };
    }

    const ParserError = enum {
        unmatched_bracket,
        missing_close_brace,
        characters_after_close_brace,
        missing_quote,
        embedded_null,
    };

    const State = enum {
        start,
        backslash,
        invalid,
        word_separator,
        command_separator,
        bare_string,
        quoted_string,
        braced_string,
        variable_subst,
        command_subst,
        comment,
    };

    pub fn next(self: *Tokenizer) Token {
        self.invalid_details = null;

        var brace_depth: u32 = undefined; // curly bracket depth
        var bracket_depth: u32 = undefined;

        var tag: Token.Tag = undefined;
        var start = self.index;
        var end: ?usize = null;
        var line_no = self.line_no;

        var state = State.start;
        while (true) {
            if (self.buffer[self.index] == '\n') self.line_no += 1;

            switch (state) {
                .start => switch (self.buffer[self.index]) {
                    0 => {
                        if (self.index == self.buffer.len) {
                            return .{
                                .tag = .end_of_file,
                                .loc = .{
                                    .start = self.index,
                                    .end = self.index,
                                    .line_no = self.line_no,
                                },
                            };
                        } else {
                            tag = .invalid;
                            self.invalid_details = .embedded_null;
                            state = .invalid;
                        }
                    },
                    '\\' => {
                        tag = .escaped_string;
                        state = .escaped_string;
                    },
                    ' ', '\t', '\r' => {
                        tag = .word_separator;
                        state = .word_separator;
                    },
                    '\n', ';' => {
                        tag = .command_separator;
                        state = .start;
                    },
                    '"' => {
                        tag = .string;
                        loc.start = self.index;
                        state = .quoted_string;
                    },
                    '{' => {
                        tag = .string;
                        brace_depth = 0;
                        loc.start = self.index;
                        state = .braced_string;
                    },
                    '$' => {
                        tag = .variable_subst;
                        loc.start = self.index;
                        state = .variable_subst;
                    },
                    '[' => {
                        tag = .command_subst;
                        bracket_depth = 0;
                        loc.start = self.index;
                        state = .command_subst;
                    },
                    '#' => {
                        state = .comment;
                    },
                    else => {
                        tag = .string;
                        state = .bare_string;
                    },
                },
                .bare_string => {
                    switch (self.buffer[self.index]) {
                        ' ', '\t', '\r', '\n', ';' => {
                            break;
                        },
                        '\\' => {
                            tag = .escaped_string;
                            // skip character after backslash
                            self.advance(1);
                        },
                        else => {},
                    }
                    self.advance(1);
                },
                .quoted_string => {
                    switch (self.buffer[self.index]) {
                        '"' => {
                            self.advance(1);
                            break;
                        },
                        '\\' => {
                            self.advance(1);
                            tag = .escaped_quoted_string;
                            self.advance(1);
                        },
                    }
                },
                .word_separator => {
                    switch (self.buffer[self.index]) {
                        ' ', '\t', '\r' => {
                            state = .word_separator;
                            self.advance(1);
                        },
                        else => break,
                    }
                },
                .command_separator => {
                    switch (self.buffer[self.index]) {
                        '\n', ';', ' ', '\t', '\r' => {
                            state = .command_separator;
                            self.advance(1);
                        },
                        else => break,
                    }
                },
                .braced_string => {
                    switch (self.buffer[self.index]) {
                        '{' => {
                            if (brace_depth == 0 and self.buffer.len - self.index >= 3) {
                                if (self.buffer[self.index + 1] == '*' and self.buffer[self.index + 2] == '}') {
                                    self.advance(3);
                                    break;
                                }
                            }

                            brace_depth += 1;
                        },
                        '}' => {
                            if (brace_depth == 0) {
                                self.invalid_details = .characters_after_close_brace;
                                state = .invalid;
                            }

                            brace_depth -= 1;
                            if (brace_depth == 0) {
                                // check that there's nothing after the close brace
                                self.advance(1);

                                switch (self.buffer[self.index]) {
                                    '\n', ';', ' ', '\t', '\r' => {
                                        break;
                                    },
                                    else => {
                                        self.invalid_details = .characters_after_close_brace;
                                        state = .invalid;
                                    },
                                }
                            }
                        },
                        else => {},
                    }

                    self.advance(1);
                },
            }
        }

        return Token{
            .tag = tag,
            .loc = .{
                .start = start,
                .end = end orelse self.index,
                .line_no = line_no,
            },
        };
    }

    fn advance(self: *Tokenizer, count: usize) void {
        self.index += count;
    }
};
