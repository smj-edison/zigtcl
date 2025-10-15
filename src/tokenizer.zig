// this is cobbled together from Molt, Zig's tokenizer, and Jimtcl

const std = @import("std");
const isWhitespace = std.ascii.isWhitespace;
const expectEqual = std.testing.expectEqual;

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
        none, // Nothing (can be safely ignored)
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
    /// Similar to `in_quote`, this keeps track of whether it's possible for the
    /// next token to be a comment (set to true after newline or semicolon).
    comment_possible: bool,
    last_token_type: Token.Tag,
    error_details: ?struct { line_no: u32, index: usize },

    const Error = error{
        missing_close_bracket,
        missing_close_brace,
        characters_after_close_brace,
        trailing_backslash,
        missing_quote,
        embedded_null,
    };

    pub fn init(buffer: []const u8) Parser {
        return .{
            .buffer = buffer,
            .index = 0,
            .line_no = 0,
            .in_quote = false,
            .comment_possible = true,
            .last_token_type = .none,
            .error_details = null,
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
                        break :blk try self.parseString();
                    },
                    '\t', 12, '\r', ' ' => {
                        if (self.in_quote) {
                            self.comment_possible = false;
                            break :blk try self.parseString();
                        } else {
                            break :blk self.parseSeparator();
                        }
                    },
                    '\n', ';' => {
                        if (self.in_quote) {
                            break :blk try self.parseString();
                        } else {
                            self.comment_possible = true;
                            break :blk self.parseEol();
                        }
                    },
                    '[' => {
                        self.comment_possible = false;
                        return self.parseCommand();
                    },
                    '$' => {
                        self.comment_possible = false;
                        self.parseVariable();
                    },
                    '#' => {
                        if (self.comment_possible) {
                            self.parseComment();
                        } else {
                            return self.parseString();
                        }
                    },
                    else => {
                        break :blk try self.parseString();
                    },
                }
            }
            break :blk null;
        };

        // If nothing was returned, it means we've reached the end of the file
        if (token) |unwrapped| {
            return unwrapped;
        } else {
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
        }
    }

    fn parseString(self: *Parser) Error!Token {
        switch (self.last_token_type) {
            .none, .word_separator, .command_separator, .simple_string, .escaped_string => {
                // This checks if we're at the start of a new word. We need to check because code such as
                // `hello[world]!` emits three tokens ("hello", "[world]", and "!"). The third token, "!",
                // would be an example where this branch would not apply.
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
                    else => {},
                }
            },
            else => {},
        }

        var token = self.newToken();
        token.tag = .simple_string;

        while (!self.atEnd()) {
            switch (self.current()) {
                '\\' => {
                    token.tag = .escaped_string;

                    if (!self.in_quote and self.peek(1) == '\n') {
                        // The escaped newline is interpreted as a word
                        // separator, so we'll cap this word.
                        token.loc.end = self.index;
                        return token;
                    }
                    self.advance(1); // skip character after \
                    try self.errorIfAtEnd(Error.trailing_backslash);

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
                        token.loc.end = self.index;
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
                        token.loc.end = self.index;
                        return token;
                    }
                },
                '$', '[' => {
                    // Start of variable/command substitution, so cap this token.
                    token.loc.end = self.index;
                    return token;
                },
                '\t'...'\r', ' ', ';' => {
                    if (!self.in_quote) {
                        token.loc.end = self.index;
                        return token;
                    }
                },
                '"' => {
                    if (self.in_quote) {
                        self.in_quote = false;
                        token.tag = .escaped_string;
                        token.loc.end = self.index;
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
            token.loc.end = self.index;
            token.tag = .escaped_string;
            return token;
        }
    }

    fn parseQuote(self: *Parser) Error!Token {
        // save for potential error message later if there's a missing close quote
        const line_no = self.line_no;
        const index = self.index;

        // skip the quote
        self.advance(1);

        var token = self.newToken();
        token.tag = .simple_string;

        while (!self.atEnd()) {
            switch (self.current()) {
                '\\' => {
                    token.tag = .escaped_string;

                    self.advance(1); // skip character after escape
                    try self.errorIfAtEnd(Error.trailing_backslash);
                },
                '"' => {
                    token.loc.end = self.index;
                    // advance past the quote
                    self.advance(1);
                    return token;
                },
                '[' => {
                    // parseCommand will advance the index just past the end of the command
                    try self.parseCommand();
                    // skip advancing this time, because parseCommand already did that
                    continue;
                },
                '$' => {
                    // Not our job to deal with variable substitution, so yield this as
                    // the end
                    token.loc.end = self.index;
                    return token;
                },
            }

            self.advance(1);
        }

        // if we made it this far, it means we reached the end of input without
        // finding a closing quote.
        self.error_details = .{
            .index = index,
            .line_no = line_no,
        };
        return Error.missing_quote;
    }

    fn parseCommand(self: *Parser) Error!Token {
        // Save in case the bracket is not matched for better error message.
        const line_no = self.line_no;
        const index = self.index;

        // Skip opening '['
        self.advance(1);
        var bracket_level: u32 = 1;

        // Whether we're at the start of a word in the command
        // (quotes and braces only apply if they're the first
        // character of a word)
        var start_of_word = true;

        var token = self.newToken();

        while (!self.atEnd()) {
            switch (self.current()) {
                '\\' => {
                    // Skip character after escape
                    self.advance(1);
                    try self.errorIfAtEnd(Error.trailing_backslash);
                },
                '[' => {
                    bracket_level += 1;
                },
                ']' => {
                    bracket_level -= 1;
                    if (bracket_level == 0) {
                        // make sure to advance past the closing bracket
                        self.advance(1);

                        token.tag = .command_subst;
                        token.end = self.index;
                        return token;
                    }
                },
                '"' => {
                    if (start_of_word) {
                        // advance to just past where the quoted word ends
                        try self.parseQuote();
                        continue;
                    }
                },
                '{' => {
                    // advance to just past where the brace ends
                    try self.parseBrace();
                    start_of_word = false; // have to set because of the continue
                    continue;
                },
                else => {
                    start_of_word = isWhitespace(self.current());
                },
            }

            self.advance(1);
        }

        // If we reached here, it means we reached the end of the input
        // without balancing our brackets. Thus, a missing bracket error
        // is needed.
        self.error_details = .{
            .line_no = line_no,
            .index = index,
        };
        return Error.missing_close_bracket;
    }

    fn parseBrace(self: *Parser) Error!Token {
        // Save the current line in case the braces are mismatched (so we can point
        // right to where the problem is)
        const line_no = self.line_no;
        const index = self.index;

        // Skip '{'
        self.advance(1);
        var brace_depth: usize = 1;

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

                        // make sure to point at after the closing brace
                        self.advance(1);

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

        self.error_details = .{
            .line_no = line_no,
            .index = index,
        };
        return Error.missing_close_brace;
    }

    fn parseEol(self: *Parser) Token {
        var token = self.newToken();

        while (!self.atEnd()) : (self.advance(1)) {
            if (!isWhitespace(self.current()) and self.current() != ';') {
                break;
            }
        }

        token.tag = .command_separator;
        token.loc.end = self.index;

        return token;
    }

    /// Parses a word separator (spaces, tabs, etc). Accounts for newline escapes.
    fn parseSeparator(self: *Parser) Token {
        var token = self.newToken();

        while (true) : (self.advance(1)) {
            switch (self.current()) {
                '\t', 12, '\r', ' ' => {},
                '\\' => {
                    if (self.peek(1) == '\n') {
                        // skip the \n
                        self.advance(1);
                    }
                },
                '\n' => break,
                else => break,
            }
        }

        token.tag = .word_separator;
        token.loc.end = self.index;

        return token;
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

    fn errorIfAtEnd(self: *Parser, error_type: Error) Error!void {
        if (self.atEnd()) {
            self.error_details = .{
                .index = self.index,
                .line_no = self.line_no,
            };
            return error_type;
        }
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

    fn startsWith(self: *Parser, str: []const u8) bool {
        if (self.buffer.len - self.index >= str.len) {
            return std.mem.eql(u8, self.buffer[self.index .. self.index + str.len], str);
        } else {
            return false;
        }
    }

    fn atEnd(self: *Parser) bool {
        return self.index == self.buffer.len;
    }
};

test "Parser" {
    const script =
        \\set x 5
        \\set y {a b c}
    ;

    var parser = Parser.init(script);

    try expectEqual((try parser.next()), Token{
        .tag = .simple_string,
        .loc = .{
            .start = 0,
            .end = 3,
            .line_no = 0,
        },
    });
    try expectEqual(.word_separator, (try parser.next()).tag);
    try expectEqual(.simple_string, (try parser.next()).tag);
    try expectEqual(.word_separator, (try parser.next()).tag);
    try expectEqual(.simple_string, (try parser.next()).tag);
    try expectEqual(.command_separator, (try parser.next()).tag);
}
