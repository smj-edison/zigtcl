// this design is very much inspired by Zig's tokenizer

const std = @import("std");
const string = @import("string_utils.zig");
const options = @import("options");

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
        argument_expansion, // Argument expansion (e.g. {*})
        variable_subst, // Variable substitution
        dict_sugar, // Syntax sugar for [dict get], $foo(bar)
        command_subst, // command substitution
        word_separator, // word separator (white space)
        command_separator, // command separator (line feed or semicolon)
        end_of_file, // end of script
        expression_sugar, // Expression sugar

        // pub fn symbol(tag: Tag) []const u8 {
        //     return switch (tag) {
        //         .string => "string",
        //         .escaped_string => "escaped string",
        //         .variable_subst => "variable substitution",
        //         .dict_sugar => "dictionary sugar",
        //         .command_subst => "command substitution",
        //         .word_separator => "word separator",
        //         .command_separator => "command separator",
        //         .end_of_file => "end of file",
        //     };
        // }
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
        dict_sugar,
        expression_sugar,
        comment,
    };

    pub fn next(self: *Tokenizer) Token {
        self.invalid_details = null;

        var brace_depth: u32 = undefined; // curly bracket depth
        var bracket_depth: u32 = undefined;
        var paren_depth: u32 = undefined; // used with dict sugar

        var tag: Token.Tag = undefined;
        var start = self.index;
        var end: ?usize = null;
        const line_no = self.line_no;

        var state = State.start;
        while (true) {
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
                    ' ', '\t', '\r', 12 => {
                        tag = .word_separator;
                        state = .word_separator;
                    },
                    '\n', ';' => {
                        tag = .command_separator;
                        state = .command_separator;
                    },
                    '"' => {
                        self.advance(1);
                        tag = .string;
                        start = self.index;
                        state = .quoted_string;
                    },
                    '{' => {
                        tag = .string;
                        brace_depth = 0;
                        start = self.index + 1;
                        state = .braced_string;
                    },
                    '$' => {
                        tag = .variable_subst;
                        start = self.index + 1;
                        state = .variable_subst;
                    },
                    '[' => {
                        tag = .command_subst;
                        bracket_depth = 0;
                        start = self.index + 1;
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
                        0, ' ', '\t', '\r', '\n', ';' => {
                            break;
                        },
                        '\\' => {
                            tag = .escaped_string;
                            // skip character after backslash
                            self.advance(1);
                        },
                        else => {},
                    }
                    if (self.index != self.buffer.len) self.advance(1);
                },
                .quoted_string => {
                    switch (self.buffer[self.index]) {
                        0 => {
                            tag = .invalid;
                            self.invalid_details = .missing_quote;
                            state = .invalid;
                        },
                        '"' => {
                            end = self.index;
                            self.advance(1);
                            break;
                        },
                        '\\' => {
                            tag = .escaped_string;
                            self.advance(1);
                            if (self.index != self.buffer.len) self.advance(1);
                        },
                        else => {},
                    }
                    state = .quoted_string;
                },
                .word_separator => {
                    switch (self.buffer[self.index]) {
                        ' ', '\t', '\r', 12 => {
                            state = .word_separator;
                            self.advance(1);
                        },
                        else => break,
                    }
                },
                .command_separator => {
                    switch (self.buffer[self.index]) {
                        '\n', ';', ' ', '\t', '\r', 12 => {
                            state = .command_separator;
                            self.advance(1);
                        },
                        else => break,
                    }
                },
                .braced_string => {
                    switch (self.buffer[self.index]) {
                        0 => {
                            tag = .invalid;
                            self.invalid_details = .missing_close_brace;
                        },
                        '{' => {
                            // check for {*}
                            if (brace_depth == 0 and self.buffer.len - self.index >= 3) {
                                if (self.buffer[self.index + 1] == '*' and self.buffer[self.index + 2] == '}') {
                                    self.advance(3);
                                    tag = .argument_expansion;
                                    break;
                                }
                            }

                            brace_depth += 1;
                        },
                        '}' => {
                            brace_depth -= 1;
                            if (brace_depth == 0) {
                                end = self.index;

                                // check that there's nothing after the close brace
                                self.advance(1);

                                switch (self.buffer[self.index]) {
                                    '\n', ';', ' ', '\t', '\r', 0 => {
                                        break;
                                    },
                                    else => {
                                        self.invalid_details = .characters_after_close_brace;
                                        state = .invalid;
                                    },
                                }
                            }
                        },
                        '\\' => {
                            // skip
                            self.advance(1);
                        },
                        else => {},
                    }

                    if (self.index != self.buffer.len) self.advance(1);
                },
                .variable_subst => {
                    self.advance(1);

                    if (options.expr_sugar) {
                        switch (self.buffer[self.index]) {
                            '[' => {
                                state = .expression_sugar;
                                continue;
                            },
                        }
                    }

                    switch (self.buffer[self.index]) {
                        0, '\n', ';', ' ', '\t', '\r', 12 => break,
                        '(' => {
                            state = .dict_sugar;
                        },
                    }
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
        for (0..count) |_| {
            if (self.buffer[self.index] == '\n') self.line_no += 1;
            self.index += 1;
        }
    }
};
