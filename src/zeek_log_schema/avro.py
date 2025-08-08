from __future__ import annotations

import json
import pickle
from dataclasses import dataclass, asdict
from itertools import chain
from typing import Any

from zeek_log_schema import zeek


# https://github.com/zeek/tree-sitter-zeek/blob/main/grammar.js#L101
def avro_type_conversion(zeek_type: str, nested_types: str | tuple[str, ...] | None = None) -> str | tuple[str, ...]:
    match zeek_type:

        case 'string' | 'enum' | 'any':
            # enum: A type allowing the specification of a set of related values that have no further structure.
            return "string"

        case 'bool':
            # Reflects a value with one of two meanings: true or false. The two bool constants are T and F.
            return "string"  # string because it's actually a 'T' or 'F' in the logs

        case 'int':
            # A numeric type representing a 64-bit signed integer.
            return "long"

        case 'count':
            # A numeric type representing a 64-bit unsigned integer.
            # TODO: there is no unsigned integer primitive in the Avro specification. There are other solutions: https://stackoverflow.com/q/74719627
            return "long"

        case 'double':
            # A numeric type representing a double-precision floating-point number.
            return "double"

        case 'time' | 'interval':
            # time: A temporal type representing an absolute time.
            # interval: A temporal type representing a relative time.
            # Both are usually output in logs as double.
            return "double"

        case 'addr' | 'subnet':
            # addr: A type representing an IP address.
            # subnet: A type representing a block of IP addresses in CIDR notation.
            return "string"

        case 'port':
            # A type representing transport-level port numbers. A port constant is written as an unsigned integer followed by one of /tcp, /udp, /icmp, or /unknown.
            return "string"

        case 'vector' | 'list' | 'set':
            # vector|list: A vector is like a table, except its indices are non-negative integers, starting from zero.
            # set: A set is like a table, but it is a collection of indices that do not map to any yield value.
            # TODO: https://avro.apache.org/docs/1.11.1/specification/#arrays

            if not nested_types:
                raise ValueError(f"No (nested) type for the items of this {zeek_type} provided.")

            # TODO: support multiple types for nested types
            return "array", avro_type_conversion(nested_types)

        case 'table':
            if not nested_types:
                raise ValueError(f"No (nested) type for the items of this {zeek_type} provided.")
            return "map"

        case 'table' | 'union' | 'pattern' | 'timer' | 'file' | 'record' | 'function' | 'event' | 'hook' | 'opaque':
            # table: An associate array that maps from one set of values to another.
            # All these types should never occur in logged fields.
            raise ValueError(f"Unsupported Zeek type provided: '{zeek_type}'.")

        case _:
            raise ValueError(f"Unrecognized Zeek type provided: '{zeek_type}'.")


def avro_type_for(field: zeek.Field) -> str | list[str]:
    if not isinstance(field.type, str):
        raise ValueError(f"Cannot determine Apache Avro type for complex, non-str Zeek field type '{type(field.type)}'.")

    avro_types = []

    # Convert Avro type
    avro_type = avro_type_conversion(field.type, field.nested_type)
    avro_types.append(avro_type)

    if field.is_optional:
        avro_types.append("null")

    return avro_types


@dataclass
class AvroField:
    name: str
    type: str | list[str]
    namespace: str = None

    items: str | None = None  # When type == "array"
    values: str | None = None  # When type == "map"

    doc: str | None = None
    default: Any | None = None

    # Non-standard field, which is supported according to the docs:
    #   "Attributes not defined in this document are permitted as metadata, but must not affect the format of serialized data."
    meta: dict[str, Any] | None = None

    @staticmethod
    def from_zeek_field(field: zeek.Field, name_prefix: str = "") -> list[AvroField]:
        """
        One Zeek field can result in multiple Avro fields when we flatten a nested zeek.RecordDeclaration.

        :param field: the zeek.Field object to process
        :param name_prefix: optional prefix to the Avro field name, useful when calling this function recursively
        :return: list of AvroField objects, to be used in an AvroSchema
        """

        fields = []

        # Flatten nested fields
        if isinstance(field.type, zeek.RecordDeclaration):
            for nested_f in field.type.fields:
                fields.extend(AvroField.from_zeek_field(nested_f, name_prefix=f"{name_prefix}{field.name}."))

        else:
            field_dict = {
                'name': f"{name_prefix}{field.name}",
                'doc': field.doc
            }

            # Add typing information
            avro_type = avro_type_for(field)
            for t in avro_type:
                if len(t) == 2:
                    if t[0] == 'array':
                        field_dict['items'] = t[1]
                    elif t[0] == 'map':
                        field_dict['values'] = t[1]
                    else:
                        raise ValueError(f"Unsupported nested type provided for '{t[0]}'")
            field_dict['type'] = avro_type

            # TODO: do we want to include meta in the avro definition?
            fields.append(AvroField(**field_dict))

        return fields


@dataclass
class AvroSchema:
    name: str
    fields: list[AvroField]
    namespace: str | None = None
    type: str = "record"
    doc: str | None = None
    aliases: list[str] | None = None

    def build(self) -> str:
        return json.dumps(asdict(self, dict_factory=lambda x: {k: v for (k, v) in x if v is not None}), indent=4)

    @staticmethod
    def from_zeek_log(stream: zeek.LogStream, namespace: str | None = None):
        schema = AvroSchema(
            name=f"{stream.path}",
            namespace=namespace,
            doc=stream.record.description,
            fields=list(chain(*map(AvroField.from_zeek_field, stream.record.fields)))
        )

        return schema


if __name__ == "__main__":
    from pathlib import Path

    streams_cache_file = Path('../res/cache/streams.pickle')
    with streams_cache_file.open('rb') as f:
        streams = pickle.load(f)

    for s in streams:
        schema = AvroSchema.from_zeek_log(s, namespace=f"zeek_6_0").build()
        if s.path == 'ssl':
            print(schema)
