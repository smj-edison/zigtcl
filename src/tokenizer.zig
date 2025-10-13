// this is cobbled together from Molt, Zig's tokenizer, and Jimtcl

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
        simple_string, // Simple string (no escaping needed)
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

const Parser = struct {
    buffer: []const u8,
    index: usize,
    line_no: u32, // current line number
    /// We need to keep track of whether we're in a quote or not across `next`
    /// invocations, because something like `set x "hello[set world]!"` emits
    /// three tokens.
    in_quote: bool,
    last_token_type: Token.Tag,
    error_details: ?struct { line_no: u32, index: usize },

    const Error = error{
        unmatched_bracket,
        missing_close_brace,
        characters_after_close_brace,
        trailing_backslash,
        missing_quote,
        embedded_null,
    };

    pub fn init(buffer: []const u8) Parser {
        // Skip the UTF-8 BOM if present.
        return .{
            .buffer = buffer,
            .index = if (std.mem.startsWith(u8, buffer, "\xEF\xBB\xBF")) 3 else 0,
            .line_no = 0,
        };
    }

    pub fn next(self: *Parser) Error!Token {
        self.error_details = null;
        const token: ?Token = blk: {
            while (!self.atEnd()) {
                switch (self.current()) {
                    '\\' => {
                        if (self.peek(1) == '\n' and !self.in_quote) {
                            // escaped newline without quotes = word separator
                            break :blk self.parseSeparator();
                        }
                        return self.parseString();
                    },
                }
            }
            break :blk null;
        };

        // If nothing was returned, it means we've reached the end of the file
        if (token == null) {
            if (self.in_quote) {
                // Ended without closing the quote
                return Error.missing_quote;
            }

            return .{
                .tag = .end_of_file,
                .loc = .{
                    .start = self.index,
                    .end = self.index,
                    .line_no = self.line_no,
                },
            };
        } else {
            return token;
        }
    }

    fn parseBrace(self: *Parser) Error!Token {
        // Save the current line in case the braces are mismatched (so we can point
        // right to where the problem is)
        self.error_details = .{ .line_no = self.line_no, .index = self.index };

        // Skip '{'
        self.advance(1);
        var brace_depth = 1;

        var token = self.newToken();

        while (!self.atEnd()) : (self.advance(1)) {
            switch (self.current()) {
                '{' => {
                    brace_depth += 1;
                },
                '}' => {
                    brace_depth -= 1;

                    if (brace_depth == 0) {
                        token.loc.end = self.index;

                        // We've found the same number of opening and closing braces
                        // at this point. We'll just double-check that there's nothing
                        // afterwards.
                        if (self.peek(1)) |char| {
                            if (!isWhitespace(char)) {
                                return Error.characters_after_close_brace;
                            }
                        }

                        token.tag = .simple_string;
                        return token;
                    }
                },
                '\\' => {
                    // we intentionally don't check for "\\n", because tcl's curly brace
                    // \n escape makes serialization of programs a pain (plus it's a rather
                    // big gotcha)
                    self.advance(1);
                    if (self.atEnd()) {
                        self.error_details = .{
                            .index = self.index,
                            .line_no = self.line_no,
                        };
                        return Error.trailing_backslash;
                    }
                },
                else => {},
            }
        }

        return Error.missing_close_brace;
    }

    fn parseQuotedWord(self: *Parser) Error!Token {
        // Skip opening quote
        self.advance(1);

        var token = self.newToken();
        token.tag = .simple_string;

        while (!self.atEnd()) : (self.advance(1)) {
            switch (self.current()) {
                '[' => {
                    token.end = self.index;
                    return token;
                },
            }
        }
    }

    /// Parses a word separator (spaces, tabs, etc). Accounts for newline escapes.
    fn parseSeparator(self: *Parser) Token {
        var token = self.newToken();

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

        token.tag = .word_separator;
        token.loc.end = self.index;

        return token;
    }

    fn parseString(self: *Parser) Token {
        switch (self.last_token_type) {
            null, .word_separator, .command_separator, .string, .escaped_string => {
                // starting a new word (we need to check because something like
                // `hello[world]!` emits three tokens ("hello", "[world]", and "!").
                // The third token, "!", would be an example where this is called,
                // not as the beginning of a word.
                switch (self.current()) {
                    '{' => return self.parseBrace(),
                    '"' => {
                        self.in_quote = true;
                        // Save where the opening quote is, so we can point to it
                        // if it's not matched.
                        self.error_details = .{
                            .index = self.index,
                            .line_no = self.line_no,
                        };
                        self.advance(1);
                    },
                }
            },
        }

        var token = self.newToken();

        while (!self.atEnd()) {
            switch (self.current()) {
                '\\' => {
                    if (!self.in_quote and self.peek(1) == '\n') {
                        // The escaped newline is interpreted as a word
                        // separator, so we'll cap this word
                        token.tag = .escaped_string;
                        token.end = self.index;
                        return token;
                    }
                    self.advance(1); // skip character after \
                    if (self.atEnd()) {
                        self.error_details = .{
                            .index = self.index,
                            .line_no = self.line_no,
                        };
                        return Error.trailing_backslash;
                    }
                    self.advance(1);
                },
                '(' => {
                    self.advance(1);
                    if (self.current() == '$') {
                        // this is for a rather obscure case, but you can do the
                        // following script: ```
                        // set x {key value}
                        // set y key
                        // set z $x($y)
                        // ```
                        // Essentially, because we encountered a $, we need to
                        // cap the current string.
                        token.tag = .escaped_string;
                        token.end = self.index;
                        return token;
                    }
                },
                ')' => {
                    self.advance(1);
                    // This branch is similar to the one above, only this is for
                    // emitting the closing ) token.

                    // Only need a separate ')' token if the previous token was a var
                    if (self.last_token_type == .variable_subst) {
                        token.tag = .escaped_string;
                        token.end = self.index;
                        return token;
                    }
                },
                '$', '[' => {
                    // Start of variable/command substitution, so cap this token.
                    token.tag = .escaped_string;
                    token.end = self.index;
                    return token;
                },
                '\t'...'\r', ' ', ';' => {
                    if (!self.in_quote) {
                        token.tag = .escaped_string;
                        token.loc.end = self.index;
                        return token;
                    }
                },
                '"' => {
                    if (self.in_quote) {
                        self.in_quote = false;
                        token.tag = .escaped_string;
                        token.end = self.index;
                        return token;
                    }
                },
                else => self.advance(1),
            }
        }

        // If we reached here, it means we reached the end of the input
        if (self.in_quote) {
            return Error.missing_quote;
        } else {
            token.end = self.index;
            token.tag = .escaped_string;
            return token;
        }
    }

    /// Initializes .start and .line_no. Caller must initialize all other fields
    fn newToken(self: *Parser) Token {
        return .{
            .tag = undefined,
            .loc = .{
                .start = self.index,
                .end = undefined,
                .line_no = self.line_no,
            },
        };
    }

    fn current(self: *Parser) u8 {
        return self.buffer[self.index];
    }

    fn peek(self: *Parser, ahead_by: usize) ?u8 {
        if (self.index + ahead_by < self.buffer.len) {
            return self.buffer[self.index + ahead_by];
        } else {
            return null;
        }
    }

    /// Handles incrementing line number
    fn advance(self: *Parser, count: usize) void {
        for (0..count) |_| {
            if (self.buffer[self.index] == '\n') self.line_no += 1;
            self.index += 1;
        }
    }

    fn startsWith(self: *Parser, string: []const u8) bool {
        if (self.buffer.len - self.index >= string.len) {
            return std.mem.eql(u8, self.buffer[self.index .. self.index + string.len], string);
        } else {
            return false;
        }
    }

    fn atEnd(self: *Parser) bool {
        return self.index == self.buffer.len;
    }
};
