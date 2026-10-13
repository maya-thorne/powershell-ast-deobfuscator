"""
PowerShell Token definitions and token types enum.
"""

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any, Optional


class TokenType(Enum):
    # Literals
    STRING_LITERAL = auto()       # 'hello' or "hello"
    NUMBER_LITERAL = auto()       # 123, 0x1A
    IDENTIFIER = auto()           # Get-Process, Invoke-Expression, iex

    # Variables
    VARIABLE = auto()             # $var, $env:PATH, ${custom:var}

    # Operators
    OP_FORMAT = auto()            # -f (format operator)
    OP_JOIN = auto()              # -join (join operator)
    OP_PLUS = auto()              # + (concatenation / addition)
    OP_PIPE = auto()              # | (pipeline)
    OP_ASSIGN = auto()            # =
    OP_DOT = auto()               # .
    OP_COLON_COLON = auto()       # :: (static member access)

    OP_RANGE = auto()             # .. (range operator)

    # Delimiters
    LPAREN = auto()               # (
    RPAREN = auto()               # )
    LBRACE = auto()               # {
    RBRACE = auto()               # }
    LBRACKET = auto()             # [ (type cast or array)
    RBRACKET = auto()             # ]
    COMMA = auto()                # ,
    SEMICOLON = auto()            # ;
    NEWLINE = auto()              # \n
    AT = auto()                   # @ (array subexpression)

    # Special
    BACKTICK_ESCAPE = auto()      # `c (escaped character)
    EOF = auto()


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int
    raw: Optional[str] = None

    def __repr__(self) -> str:
        return f"Token({self.type.name}, {self.value!r}, L{self.line}:C{self.column})"
