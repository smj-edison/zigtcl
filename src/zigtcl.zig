const std = @import("std");
const string = @import("string_utils.zig");

const empty_string = "";

const TclParser = struct {
    

    /// Results of missing quotes, braces, etc. from parsing.
    const ParseMissing = struct {
        ch: u8, // At end of parse, ' ' if complete or '{', '[', '"', '\\', '}' if incomplete
        int: usize, // Line number starting the missing token
    };

    

    

    

    fn remainingBytes(self: *Tokenizer) usize {
        return self.program.len -| self.iter.i;
    }

    pub fn next(self: *Tokenizer) ParserError!Token {
        const token = blk: while (self.iter.next()) |cp| {
            if (self.iter.idx >= self.program.len) {
                if (self.in_quote) {
                    // TODO: is this check needed?
                    self.error_details.missing_char = '"';
                    return ParserError.UnexpectedEof;
                }

                break :blk Token{
                    .token_type = .end_of_file,
                    .source = null,
                    .line_no = self.line_no,
                };
            }

            switch (cp) {
                '\\' => {
                    // line escape?
                    if (self.iter.peek() == '\n' and !self.in_quote) {
                        break :blk try self.parseSeperator(cp);
                    }
                    // else it's a character escape (e.g. start of a string)
                    break :blk try self.parseString(cp);
                },
            }
        };

        self.last_token = token;
        return token;
    }

    fn parseSeperator(self: *Tokenizer, cp: string.Codepoint) ParserError!Token {
        const token_start = self.iter.i;
        const token_line = self.line_no;

        while (self.iter.next()) |cp| {
            if (string.isWhitespace(cp)) {
                if (cp == '\n') break;
            } else if (cp == '\\' and self.iter.peek() == '\n') {
                _ = self.iter.next(); // skip \n
                self.line_no += 1;
            } else break;
        }

        return Token{
            .token_type = .separator,
            .source = self.program[token_start..self.iter.i],
            .line_no = token_line,
        };
    }

    fn parseString(self: *Tokenizer, cp: string.Codepoint) ParserError!Token {
        if (cp == '{') {
            return self.parseBrace();
        } else if (cp == '"') {
            self.in_quote = true;
            _ = self.iter.next();
        }

        const token_start = self.iter.i;
        const token_line = self.line_no;

        var current = cp;
        while (true) : (current = self.iter.next()) {
            const next = self.iter.peek();
            if (next == null) {
                if (self.in_quote) {
                    self.error_details.missing_char = '"';
                    return ParserError.UnexpectedEof;
                }

                return Token{
                    .token_type = .escaped_string,
                    .source = self.program[token_start..self.iter.i],
                    .line_no = token_line,
                };
            }

            switch (current) {
                '\\' => {
                    if (!self.in_quote and next == '\n') {
                        return Token{
                            .token_type = .escaped_string,
                            .source = self.program[token_start..self.iter.i],
                            .line_no = token_line,
                        };
                    } else if (next == '\n') {
                        
                    }
                },
                '(' => {

                }
            }
        }

        @panic("parseString called with zero-length range")
    }
};
