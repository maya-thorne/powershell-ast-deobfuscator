"""
PowerShell Lexical Scanner & Tokenizer.
Handles backtick escapes (`), format operators (-f), variables, and string literal variations.
"""

import re
from typing import List, Optional

from .tokens import Token, TokenType


class PowerShellLexer:
    """
    Scans raw PowerShell script code into a stream of tokens.
    """

    def __init__(self, source: str):
        self.source = source
        self.pos = 0
        self.length = len(source)
        self.line = 1
        self.column = 1
        self.bracket_depth = 0

    def peek(self, offset: int = 0) -> Optional[str]:
        idx = self.pos + offset
        if idx < self.length:
            return self.source[idx]
        return None

    def advance(self) -> Optional[str]:
        if self.pos < self.length:
            ch = self.source[self.pos]
            self.pos += 1
            if ch == "\n":
                self.line += 1
                self.column = 1
            else:
                self.column += 1
            return ch
        return None

    def skip_whitespace_and_comments(self) -> None:
        while self.pos < self.length:
            ch = self.source[self.pos]

            # Block comment <# ... #>
            if ch == "<" and self.peek(1) == "#":
                self.pos += 2
                self.column += 2
                while self.pos < self.length:
                    if self.source[self.pos] == "#" and self.peek(1) == ">":
                        self.pos += 2
                        self.column += 2
                        break
                    if self.source[self.pos] == "\n":
                        self.line += 1
                        self.column = 1
                    else:
                        self.column += 1
                    self.pos += 1
                continue

            # Single-line comment # ...
            if ch == "#":
                while self.pos < self.length and self.source[self.pos] != "\n":
                    self.pos += 1
                    self.column += 1
                continue

            # Whitespace
            if ch in (" ", "\t", "\r"):
                self.pos += 1
                self.column += 1
                continue

            break

    def read_single_quoted_string(self) -> Token:
        start_line = self.line
        start_col = self.column
        self.advance()  # Skip leading '

        buf = []
        raw_chars = ["'"]
        while self.pos < self.length:
            ch = self.advance()
            raw_chars.append(ch)
            if ch == "'":
                if self.peek() == "'":
                    # Escaped single quote ''
                    self.advance()
                    raw_chars.append("'")
                    buf.append("'")
                else:
                    break
            else:
                buf.append(ch)

        return Token(
            type=TokenType.STRING_LITERAL,
            value="".join(buf),
            line=start_line,
            column=start_col,
            raw="".join(raw_chars),
        )

    def read_double_quoted_string(self) -> Token:
        start_line = self.line
        start_col = self.column
        self.advance()  # Skip leading "

        buf = []
        raw_chars = ['"']
        while self.pos < self.length:
            ch = self.advance()
            raw_chars.append(ch)
            if ch == '"':
                break
            elif ch == "`":
                # Backtick escape inside double quotes
                if self.pos < self.length:
                    esc = self.advance()
                    raw_chars.append(esc)
                    if esc == "0":
                        buf.append("\0")
                    elif esc == "a":
                        buf.append("\a")
                    elif esc == "b":
                        buf.append("\b")
                    elif esc == "f":
                        buf.append("\f")
                    elif esc == "n":
                        buf.append("\n")
                    elif esc == "r":
                        buf.append("\r")
                    elif esc == "t":
                        buf.append("\t")
                    elif esc == "v":
                        buf.append("\v")
                    elif esc == "`":
                        buf.append("`")
                    elif esc == '"':
                        buf.append('"')
                    elif esc == "'":
                        buf.append("'")
                    elif esc == "$":
                        buf.append("$")
                    else:
                        buf.append(esc)  # e.g., `H -> H
            else:
                buf.append(ch)

        return Token(
            type=TokenType.STRING_LITERAL,
            value="".join(buf),
            line=start_line,
            column=start_col,
            raw="".join(raw_chars),
        )

    def read_variable(self) -> Token:
        start_line = self.line
        start_col = self.column
        self.advance()  # Skip $

        # Check for braced variable ${...}
        if self.peek() == "{":
            self.advance()
            buf = []
            while self.pos < self.length and self.source[self.pos] != "}":
                ch = self.advance()
                if ch == "`" and self.pos < self.length and self.source[self.pos] != "}":
                    buf.append(self.advance())
                else:
                    buf.append(ch)
            if self.pos < self.length and self.source[self.pos] == "}":
                self.advance()
            return Token(
                type=TokenType.VARIABLE,
                value="".join(buf),
                line=start_line,
                column=start_col,
            )

        buf = []
        while self.pos < self.length:
            ch = self.source[self.pos]
            if ch == "`":
                self.advance()
                if self.pos < self.length:
                    buf.append(self.advance())
                continue
            if ch.isalnum() or ch in ("_", ":", "?"):
                buf.append(self.advance())
            else:
                break

        return Token(
            type=TokenType.VARIABLE,
            value="".join(buf),
            line=start_line,
            column=start_col,
        )

    def read_number_or_identifier(self) -> Token:
        start_line = self.line
        start_col = self.column
        buf = []

        # Check for hex number 0x...
        if self.source[self.pos] == "0" and self.peek(1) in ("x", "X"):
            buf.append(self.advance())
            buf.append(self.advance())
            while self.pos < self.length and self.source[self.pos].isalnum():
                buf.append(self.advance())
            val_str = "".join(buf)
            try:
                num = int(val_str, 16)
                return Token(type=TokenType.NUMBER_LITERAL, value=str(num), line=start_line, column=start_col, raw=val_str)
            except ValueError:
                pass

        # Check for decimal number
        if self.source[self.pos].isdigit():
            while self.pos < self.length:
                if self.source[self.pos] == "." and self.peek(1) == ".":
                    # '..' range operator upcoming - stop reading number
                    break
                if self.source[self.pos].isdigit() or self.source[self.pos] == ".":
                    buf.append(self.advance())
                else:
                    break
            val_str = "".join(buf)
            return Token(type=TokenType.NUMBER_LITERAL, value=val_str, line=start_line, column=start_col, raw=val_str)

        # Identifier or command
        while self.pos < self.length:
            ch = self.source[self.pos]
            # Backtick escaping inside identifier (classic PowerShell evasion: In`voke-Exp`ression)
            if ch == "`":
                self.advance()  # Skip backtick
                if self.pos < self.length:
                    buf.append(self.advance())
                continue

            if ch.isalnum() or ch in ("_", "-", "\\"):
                buf.append(self.advance())
            elif ch == "." and self.peek(1) != ".":
                # Type / namespace identifier dot allowed inside [Type.Name]
                if self.bracket_depth > 0 and self.peek(1) and (self.peek(1).isalnum() or self.peek(1) == "_"):
                    buf.append(self.advance())
                else:
                    break
            else:
                break

        val = "".join(buf)
        return Token(type=TokenType.IDENTIFIER, value=val, line=start_line, column=start_col)

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []

        while self.pos < self.length:
            self.skip_whitespace_and_comments()
            if self.pos >= self.length:
                break

            ch = self.source[self.pos]
            line = self.line
            col = self.column

            # Newlines
            if ch == "\n":
                self.advance()
                tokens.append(Token(TokenType.NEWLINE, "\n", line, col))
                continue

            # Semicolon
            if ch == ";":
                self.advance()
                tokens.append(Token(TokenType.SEMICOLON, ";", line, col))
                continue

            # Delimiters
            if ch == "(":
                self.advance()
                tokens.append(Token(TokenType.LPAREN, "(", line, col))
                continue
            if ch == ")":
                self.advance()
                tokens.append(Token(TokenType.RPAREN, ")", line, col))
                continue
            if ch == "{":
                self.advance()
                tokens.append(Token(TokenType.LBRACE, "{", line, col))
                continue
            if ch == "}":
                self.advance()
                tokens.append(Token(TokenType.RBRACE, "}", line, col))
                continue
            if ch == "[":
                self.advance()
                self.bracket_depth += 1
                tokens.append(Token(TokenType.LBRACKET, "[", line, col))
                continue
            if ch == "]":
                self.advance()
                self.bracket_depth = max(0, self.bracket_depth - 1)
                tokens.append(Token(TokenType.RBRACKET, "]", line, col))
                continue
            if ch == ",":
                self.advance()
                tokens.append(Token(TokenType.COMMA, ",", line, col))
                continue
            if ch == "@":
                self.advance()
                tokens.append(Token(TokenType.AT, "@", line, col))
                continue

            # Operators
            if ch == "|":
                self.advance()
                tokens.append(Token(TokenType.OP_PIPE, "|", line, col))
                continue
            if ch == "+":
                self.advance()
                tokens.append(Token(TokenType.OP_PLUS, "+", line, col))
                continue
            if ch == "=":
                self.advance()
                tokens.append(Token(TokenType.OP_ASSIGN, "=", line, col))
                continue
            if ch == ":" and self.peek(1) == ":":
                self.advance()
                self.advance()
                tokens.append(Token(TokenType.OP_COLON_COLON, "::", line, col))
                continue
            if ch == ".":
                if self.peek(1) == ".":
                    self.advance()
                    self.advance()
                    tokens.append(Token(TokenType.OP_RANGE, "..", line, col))
                    continue
                else:
                    self.advance()
                    tokens.append(Token(TokenType.OP_DOT, ".", line, col))
                    continue

            # Operators: '-join', '-f', or negative numbers
            if ch == "-":
                remaining = self.source[self.pos:]
                if re.match(r"^-join\b", remaining, re.IGNORECASE):
                    self.pos += 5
                    self.column += 5
                    tokens.append(Token(TokenType.OP_JOIN, "-join", line, col))
                    continue
                if self.peek(1) in ("f", "F") and (self.pos + 2 >= self.length or not self.source[self.pos + 2].isalnum()):
                    self.advance()
                    self.advance()
                    tokens.append(Token(TokenType.OP_FORMAT, "-f", line, col))
                    continue
                if self.peek(1) and self.peek(1).isdigit():
                    last_type = tokens[-1].type if tokens else None
                    if last_type in (
                        None,
                        TokenType.LPAREN,
                        TokenType.LBRACKET,
                        TokenType.COMMA,
                        TokenType.OP_RANGE,
                        TokenType.OP_ASSIGN,
                        TokenType.OP_PIPE,
                        TokenType.OP_JOIN,
                        TokenType.SEMICOLON,
                        TokenType.NEWLINE,
                    ):
                        self.advance()  # consume '-'
                        num_tok = self.read_number_or_identifier()
                        num_tok.value = f"-{num_tok.value}"
                        if num_tok.raw:
                            num_tok.raw = f"-{num_tok.raw}"
                        tokens.append(num_tok)
                        continue

            # String literals
            if ch == "'":
                tokens.append(self.read_single_quoted_string())
                continue
            if ch == '"':
                tokens.append(self.read_double_quoted_string())
                continue

            # Variables
            if ch == "$":
                tokens.append(self.read_variable())
                continue

            # Standalone backtick
            if ch == "`":
                self.advance()
                if self.pos < self.length:
                    esc_char = self.advance()
                    tokens.append(Token(TokenType.BACKTICK_ESCAPE, esc_char, line, col))
                continue

            # Identifiers and Numbers
            if ch.isalnum() or ch in ("_", "-"):
                tokens.append(self.read_number_or_identifier())
                continue

            # Fallback single character
            self.advance()
            tokens.append(Token(TokenType.IDENTIFIER, ch, line, col))

        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens
