# To support circular dependencies in dataclasses
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Generator


class ParseError(Exception):
    pass


@dataclass
class MemoryFile:
    path: Path
    contents: BytesIO


@dataclass
class LazyIdentifier(str):
    """Temporary placeholder for an identifier, for example a record name that we substitute later for its record declaration."""

    name: str


@dataclass(order=True)
class LogStream:
    path: str
    id: str
    columns: str
    meta: dict[str, Any] | None = None
    record: RecordDeclaration | None = None


@dataclass
class RecordDeclaration:
    name: str
    fields: list[Field]
    is_redef: bool

    description: str | None = None
    meta: dict[str, Any] | None = None

    # Attributes
    is_logged: bool = False

    def filter_fields(self, filter_fn: Callable, recursive=True) -> None:
        """Flattens nested RecordDeclarations."""

        def field_gen(fields: list[Field]) -> Generator[Field, None, None]:
            for f in fields:
                if filter_fn(f):
                    if recursive and isinstance(f.type, RecordDeclaration):
                        f.type.filter_fields(filter_fn, recursive=recursive)
                    yield f

        self.fields = list(field_gen(self.fields))

    def expand_nested_fields(self) -> None:
        """
        - Recursively merge nested RecordDeclaration fields
        - Namespace field names
        """

        def field_gen(
                fields: list[Field], prefix: str = ""
        ) -> Generator[Field, None, None]:
            for f in fields:
                if isinstance(f.type, RecordDeclaration):
                    yield from field_gen(f.type.fields, prefix=f"{prefix}{f.name}.")

                else:
                    updated_f = deepcopy(f)
                    updated_f.name = f"{prefix}{f.name}"
                    yield updated_f

        self.fields = list(field_gen(self.fields))


@dataclass
class Field:
    name: str
    type: str | RecordDeclaration | None = None
    nested_type: str | tuple[str, ...] | None = None
    doc: str | None = None
    meta: dict[str, Any] | None = None

    # Attributes
    is_logged: bool = False
    is_redef: bool = False
    is_optional: bool = False
    is_deprecated: bool = False
    default: str | None = None

    def __str__(self):
        _str = f"Field: {self.name}"

        if self.type:
            if self.nested_type:
                _str += f" ({self.type} + {self.nested_type})"
            else:
                _str += f" ({self.type})"

        if self.is_logged:
            _str += " &log;"
        if self.is_redef:
            _str += " &redef;"
        if self.is_optional:
            _str += " &optional;"
        if self.is_deprecated:
            _str += " &deprecated;"
        if self.default:
            _str += f" &default={self.default};"

        return _str
