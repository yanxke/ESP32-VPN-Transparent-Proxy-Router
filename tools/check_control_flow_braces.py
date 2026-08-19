#!/usr/bin/env python3
"""Reject unbraced if/else/for/while bodies in C source files."""

from __future__ import annotations

import sys
from pathlib import Path


def tokens(source: str) -> list[tuple[str, int, int]]:
    """Tokenize enough C syntax for structural control-flow checks."""
    result: list[tuple[str, int, int]] = []
    index = 0
    line = 1
    column = 1
    at_line_start = True

    def advance() -> str:
        nonlocal index, line, column, at_line_start
        character = source[index]
        index += 1
        if character == "\n":
            line += 1
            column = 1
            at_line_start = True
        else:
            column += 1
            if not character.isspace():
                at_line_start = False
        return character

    while index < len(source):
        character = source[index]
        if character.isspace():
            advance()
            continue
        if character == "#" and at_line_start:
            while index < len(source):
                continued = index > 0 and source[index - 1] == "\\"
                if advance() == "\n" and not continued:
                    break
            continue
        if source.startswith("//", index):
            while index < len(source) and advance() != "\n":
                pass
            continue
        if source.startswith("/*", index):
            advance()
            advance()
            while index < len(source) and not source.startswith("*/", index):
                advance()
            if index < len(source):
                advance()
                advance()
            continue
        if character in "\"'":
            quote = advance()
            while index < len(source):
                value = advance()
                if value == "\\" and index < len(source):
                    advance()
                elif value == quote:
                    break
            continue
        token_line, token_column = line, column
        if character.isalpha() or character == "_":
            start = index
            while index < len(source) and (source[index].isalnum() or source[index] == "_"):
                advance()
            result.append((source[start:index], token_line, token_column))
            continue
        result.append((advance(), token_line, token_column))
    return result


def matching_paren(items: list[tuple[str, int, int]], opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(items)):
        if items[index][0] == "(":
            depth += 1
        elif items[index][0] == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def verify(path: Path) -> list[str]:
    items = tokens(path.read_text(encoding="utf-8"))
    failures: list[str] = []
    for index, (value, line, column) in enumerate(items):
        if value in {"if", "for", "while"}:
            if index + 1 >= len(items) or items[index + 1][0] != "(":
                continue
            closing = matching_paren(items, index + 1)
            if closing is None or closing + 1 >= len(items):
                continue
            body = items[closing + 1][0]
            # A trailing while is the condition of a do/while statement.
            if value == "while" and body == ";":
                continue
            if body != "{":
                failures.append(f"{path}:{line}:{column}: {value} body must use braces")
        elif value == "else" and index + 1 < len(items):
            body = items[index + 1][0]
            if body not in {"{", "if"}:
                failures.append(f"{path}:{line}:{column}: else body must use braces")
    return failures


def main() -> int:
    failures = [failure for name in sys.argv[1:] for failure in verify(Path(name))]
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
