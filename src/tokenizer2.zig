const std = @import("std");
const isWhitespace = std.ascii.isWhitespace;
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
        invalid, // Malformed input
        escaped_string, // String that needs escape character conversion
        argument_expansion, // Argument expansion (e.g. {*})
        variable_subst, // Variable substitution
        dict_sugar, // Syntax sugar for [dict get], $foo(bar)
        command_subst, // command substitution
        word_separator, // word separator (white space)
        command_separator, // command separator (line feed or semicolon)
        end_of_file, // end of script
        expression_sugar, // Expression sugar
    };
};

const Tokenizer = struct {
    buffer: []const u8,
    index: usize,
    last_token_type: ?Token.Tag,
    in_quote: bool, // Parsing a quoted string
    line_no: u32, // current line number
    invalid_details: InvalidDetails,

    const InvalidDetails = enum {
        unmatched_bracket,
        missing_close_brace,
        characters_after_close_brace,
        trailing_backslash,
        missing_quote,
        embedded_null,
    };

    pub fn init(buffer: []const u8) Tokenizer {
        // Skip the UTF-8 BOM if present.
        return .{
            .buffer = buffer,
            .index = if (std.mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0,
            .last_token_type = null,
            .in_quote = false,
            .line_no = 0,
            .invalid_details = null,
        };
    }

    pub fn next(self: *Tokenizer) Token {
        self.invalid_details = null;

        const token = blk: while (true) {
            if (self.index == self.buffer) {
                break :blk .{
                    .tag = .end_of_file,
                    .loc = .{
                        .start = self.index,
                        .end = self.index,
                        .line_no = self.line_no,
                    },
                };
            }

            switch (self.buffer[self.index]) {
                '\\' => {
                    if (self.peek(1) == '\n' and !self.in_quote) {
                        break :blk self.parseSeparator();
                    }
                },
            }
        };

        self.last_token_type = token.tag;
        return token;
    }

    fn parseSeparator(self: *Tokenizer) Token {
        const start = self.index;
        const line_no = self.line_no;

        while (true) {
            switch (self.current()) {
                '\t', 11, 12, '\r', ' ' => {},
                '\\' => {
                    if (self.peek(1) == '\n') {
                        // skip the \n
                        self.advance(1);
                    }
                },
                '\n' => break,
                else => break,
            }

            self.advance(1);
        }

        return .{
            .tag = .word_separator,
            .loc = .{
                .start = start,
                .end = self.index,
                .line_no = line_no,
            },
        };
    }

    fn parseString(self: *Tokenizer) Token {
        switch (self.last_token_type) {
            null, .word_separator, .command_separator, .string, .escaped_string => {
                // starting a new word
                switch (self.current()) {
                    '{' => return self.parseBrace(),
                    '"' => {
                        self.in_quote = true;
                        self.advance(1);
                    },
                }
            },
        }

        var token = Token{ .tag = undefined, .loc = .{
            .start = self.index,
            .end = undefined,
            .line_no = self.line_no,
        } };

        while (true) : (self.advance(1)) {
            if (self.index == self.buffer.len) {
                if (self.in_quote) {
                    self.invalid_details = .missing_quote;
                    token.tag = .invalid;
                    token.end = self.index;
                    return token;
                } else {
                    token.tag = .escaped_string;
                    token.end = self.index;
                    return token;
                }

                switch (self.current()) {
                    '\\' => {
                        if (!self.in_quote and self.peek(1) == '\n') {
                            // end of word (escaped newline)
                            token.tag = .escaped_string;
                            token.end = self.index;
                            return token;
                        }

                        if (self.buffer.len - self.index >= 2) {
                            self.advance(1); // skip character after \
                        } else {
                            self.invalid_details = .trailing_backslash;
                            token.tag = .invalid;
                            token.end = self.index;
                            return token;
                        }
                    },
                    '(', ')' => {
                        if (self.current() == '$',  self.peek(1) == '$') {

                        }
                    }
                }
            }
        }
    }

    fn parseBrace(self: *Tokenizer) Token {
        const start = self.index;
        const line_no = self.line_no;

        // skip the brace
        self.advance(1);
        var brace_level = 1;

        while (self.index < self.buffer.len) : (self.advance(1)) {
            switch (self.current()) {
                '\\' => {
                    self.advance(1);
                },
                '{' => {
                    brace_level += 1;
                },
                '}' => {
                    brace_level -= 1;
                    if (brace_level == 0) {
                        self.advance(1);
                        return .{
                            .tag = .bare_string,
                            .loc = .{
                                .start = start,
                                .end = self.index,
                                .line_no = line_no,
                            },
                        };
                    }
                },
                else => {},
            }
        }

        self.invalid_details = .missing_close_brace;
        return .{
            .tag = .invalid,
            .loc = .{
                .start = start,
                .end = self.index,
                .line_no = line_no,
            },
        };
    }

    fn current(self: *Tokenizer) u8 {
        return self.buffer[self.index];
    }

    fn peek(self: *Tokenizer, ahead_by: usize) ?u8 {
        if (self.index + ahead_by < self.buffer.len) {
            return self.buffer[self.index + ahead_by];
        } else {
            return null;
        }
    }

    /// Handles incrementing line number
    fn advance(self: *Tokenizer, count: usize) void {
        for (0..count) |_| {
            if (self.buffer[self.index] == '\n') self.line_no += 1;
            self.index += 1;
        }
    }
};
