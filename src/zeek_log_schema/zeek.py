import sys
from collections import defaultdict
from copy import deepcopy
from io import BytesIO
from itertools import chain
from pathlib import Path
from typing import Generator, Iterable

from zeekscript import Script
from zeekscript.node import Node

from zeek_log_schema.models import Field, LazyIdentifier, LogStream, MemoryFile, ParseError, RecordDeclaration
from zeek_log_schema.util import first_child_with_name, normalize_identifier_with_namespace


class ZeekScriptParser:
    def __init__(self, input_file: Path | MemoryFile, relative_to_scripts: bool = True):

        if isinstance(input_file, MemoryFile):
            path = input_file.path
            source = input_file.contents
            self.file = path
        else:
            path = input_file
            source = input_file

            full_path = str(path.absolute().with_suffix(''))

            if relative_to_scripts and 'scripts/' in full_path:
                # Find the path relative to 'scripts/'
                # Also strip extension to allow Bro / Zeek comparisons
                _, relative_path = full_path.rsplit('scripts/', maxsplit=1)
                self.file = f"scripts/{relative_path}"

            else:
                self.file = full_path

        # Parse ZeekScript file (build TreeSitter tree)
        self.script: Script = ZeekScriptParser.read_zeekscript(source)

    def text(self, node: Node) -> str:
        """
        Render tree-sitter node as text.

        :param node: Which node to render
        :return: String representation of node
        """
        return self.script.get_content(*node.script_range()).decode()

    def parse(self) -> dict:

        # Result stores
        streams = []
        records = []
        types: dict[str, str] = {}

        # Current namespace
        current_namespace = 'global'

        # Find and traverse interesting nodes
        for node, _ in self.script.root.traverse(predicate=lambda n: n.name() in ('module_decl', 'type_decl', 'redef_record_decl') or (
                # Stream definition
                n.name() == 'expr' and self.text(n).strip().lower().startswith('log::create_stream') and any(c for c in n.nonerr_children if c.name() == 'expr_list')
        ), include_cst=True):

            match node.name():

                # Switch namespace declaration
                case 'module_decl':

                    current_namespace = self._parse_module_declaration(node)
                    continue

                # Record or other type (re)declaration
                case 'type_decl' | 'redef_record_decl':

                    # Initially, we only analyzed declarations inside export {} blocks. However, some modules / plug-ins declare their records outside those blocks.
                    # Therefore, we just parse everything and filter for interesting declarations afterwards.

                    if node.name() == 'redef_record_decl' or (
                            # type_decl: $ => seq('type', $.id, ':', $.name(), optional($.attr_list), ';')
                            node.name() == 'type_decl' and node.children[3].children[0].type == 'record'
                    ):

                        # Record (re)declaration
                        if parsed_record := self._parse_record_declaration(node, current_namespace):
                            records.append(parsed_record)

                    else:

                        # Other type declaration
                        if parsed_type := self._parse_other_type_declaration(node, current_namespace):
                            type_name, type_type = parsed_type

                            if type_name in types:
                                raise ValueError("Redefined (type_decl ...) that are not of type 'record' are currently unsupported.")

                            # Store in type dict
                            types[type_name] = type_type

                    continue

                # Log stream creation (due to the predicate provided to traverse(), which only selects those (expr ..) nodes)
                case 'expr':

                    if parsed_stream := self._parse_log_create_stream(node, current_namespace):
                        streams.append(parsed_stream)

                    continue

        return {
            'streams': streams,
            'records': records,
            'types': types
        }

    def _parse_module_declaration(self, node: Node) -> str:
        """
        # Module declarations define the namespace of subsequent type declarations
        # If no module declaration was found, or the module is declared GLOBAL, the type declarations have no namespace
        # Else, we need to store the namespace with the declared type.

        :param node: (module_decl ...) node
        :return: name of the current namespace
        """

        # Name of this module is in the first (and only) "id" node occurrence
        _id = first_child_with_name(node, 'id')
        return self.text(_id).lower() if _id else 'global'

    def _parse_record_declaration(self, node: Node, namespace: str = 'global') -> RecordDeclaration:
        """

        For reference:
            type_decl: $ => seq('type', $.id, ':', $.type, optional($.attr_list), ';')
            redef_record_decl: $ => seq('redef', 'record', $.id, '+=', '{', repeat($.type_spec), '}', optional($.attr_list), ';'),

        :param node: either a (type_decl ...) node whose $.type == 'record', or a (redef_record_decl ...) node
        :param namespace:
        :return: parsed RecordDeclaration
        """

        # Initialize record declaration dict
        record_declaration = {
            'meta': {
                'filename': self.file
            },
            'is_redef': node.name() == 'redef_record_decl'
        }

        # Parse record name
        _id = first_child_with_name(node, 'id')
        if not _id:
            raise ParseError("Could not extract record ID.")

        record_declaration['name'] = normalize_identifier_with_namespace(self.text(_id), namespace)

        # Parse field declarations -> (type_spec ...)
        record_declaration['fields'] = []
        for inner_node, _ in node.traverse(predicate=lambda n: n.name() == 'type_spec', include_cst=True):
            if inner_node.name() == 'type_spec':
                if field := self._parse_field_declaration(inner_node, namespace):
                    record_declaration['fields'].append(field)

        # Parse record attributes
        if _attr_list := list(filter(lambda n: n.name() == 'attr_list', node.children)):
            for attr_node, _ in _attr_list[0].traverse(predicate=lambda n: n.name() == 'attr'):

                # Some attributes comprise multiple child nodes (e.g. 'default', '=', '0')
                attr_name = self.text(attr_node.nonerr_children[0]) if len(attr_node.nonerr_children) > 1 else self.text(attr_node)

                match attr_name:
                    case '&log':
                        record_declaration['is_logged'] = True

                        # Update is_logged metadata on all fields in this struct
                        for f in record_declaration['fields']:
                            f.is_logged = True

                        continue

                    case '&redef':
                        # This is different from the (redef_record_decl ...) statement
                        record_declaration['meta']['is_redef'] = True
                        continue

                    case _:
                        raise NotImplementedError(f"Unsupported attribute found in ({node.name()} ...) declaration. Attribute: '{attr_name}', content: '{self.text(attr_node)}'")

        # Find description of record (if any)
        # N.B. we have to use node.parent, because a (type_decl ...) or (redef_record_decl ...) are always wrapped with a (decl ...) node.
        # The comment is a sibling of this (decl ...) node.
        record_declaration['description'] = '\n'.join(filter(None, [
            self.get_comment_for(node.parent, 'zeekygen_next_comment'),
            self.get_comment_for(node.parent, 'zeekygen_prev_comment')
        ]))

        return RecordDeclaration(**record_declaration)

    def _parse_field_declaration(self, node: Node, namespace: str = 'global') -> Field | None:
        """
        Parses a (type_spec ...) declaration.

        :param node: a (type_spec ...) node.
        :param namespace: the namespace in which this field is declared.
        :return: parsed Field object for this node
        """

        # Initialize field declaration dict
        field_declaration = {
            'meta': {
                'filename': self.file
            }
        }

        # Process all children of this field definition node
        for field_node in node.nonerr_children:

            match field_node.name():
                case 'id':  # Required
                    field_declaration['name'] = self.text(field_node).lower()

                case 'type':  # Required
                    # TODO: default to module namespace if in export block
                    field_declaration['type'], field_declaration['nested_type'] = self.get_type_name(field_node, namespace)
                    pass

                case 'attr_list':  # Optional
                    for attr_node, _ in field_node.traverse(predicate=lambda n: n.name() == 'attr'):

                        # Some attributes comprise multiple child nodes (e.g. 'default', '=', '0')
                        attr_name = self.text(attr_node.nonerr_children[0]) if len(attr_node.nonerr_children) > 1 else self.text(attr_node)

                        match attr_name:
                            case '&log':
                                field_declaration['is_logged'] = True

                            case '&redef':
                                field_declaration['is_redef'] = True

                            case '&optional':
                                field_declaration['is_optional'] = True

                            case '&deprecated':
                                field_declaration['is_deprecated'] = True

                            case '&default':
                                field_declaration['default'] = self.text(attr_node.nonerr_children[2])

                            case '&ordered' | '&read_expire' | '&create_expire' | '&expire_func' | '&write_expire' | '&deprecated':
                                pass

                            case _:
                                raise NotImplementedError(f"Unsupported attribute found in (type_spec ...) declaration. Attribute: '{attr_name}', content: '{self.text(attr_node)}'")

                case None:  # Ignore unnamed entries / tokens
                    pass

                case _:
                    # Not-yet-implemented parts of a type_spec declaration.
                    raise NotImplementedError(f"Unsupported (type_spec ...) node found: '{self.text(field_node)}'")

            # Discard fields that are not logged

            # Finally, lookup (zeekygen_next_comment ...) description nodes
            field_declaration['doc'] = '\n'.join(filter(None, [
                self.get_comment_for(node, 'zeekygen_next_comment'),
                self.get_comment_for(node, 'zeekygen_prev_comment')
            ]))

        # Create field and return
        field = Field(**field_declaration)
        return field

    def _parse_other_type_declaration(self, node: Node, namespace: str = 'global') -> tuple[str, tuple[str, ...] | str]:
        """
        Besides record declarations, we may also be interested in other types, such a enums.
        These types describe the format of output (log) data, so it's important to take those into consideration.

        N.B.: --NO-- support for redef 'other' type declarations. It does not make sense to change existing types, the syntax is however supported.

        :param node: (type_decl ...) node
        :param namespace: current namespace
        :return: tuple with the name and the type of the declared type
        """

        type_name = normalize_identifier_with_namespace(self.text(node.children[1]), namespace)
        # TODO: support nested types for 'other' types. We now discard this information here (i.e. set[string] becomes just set)
        type_type, type_nested_type = self.get_type_name(node.children[3], namespace)
        if type_nested_type:
            return type_name, (type_type, type_nested_type)
        else:
            return type_name, type_type

    def _parse_log_create_stream(self, node: Node, namespace: str = 'global') -> LogStream | None:
        """
        Parse a Log::create_stream() declaration.
          - before Zeek 8.0: `Log::create_stream(X509::LOG, [$columns=Info, $ev=log_x509, $path="x509", $policy=log_policy]);`
          - since Zeek 8.0:  `Log::create_stream(X509::LOG, Log::Stream([$columns=Info, $ev=log_x509, $path="x509", $policy=log_policy]));`

        :param node: (expr ...) node of the Log::create_stream statement
        :param namespace: current namespace
        :return: parsed CreateStreamDefinition
        """

        # Get (expr_list ...) for this expressions
        expr_list = first_child_with_name(node, 'expr_list')

        if not expr_list or len(expr_list.children) != 3:
            raise ParseError("Could not parse Log::create_stream() statement: (expr_list ...) does not have exactly three children.")

        # Ignore, just assume we end up with the node that contains the array of create_stream attributes
        id_node, _, stream_definition = expr_list.children

        if len(stream_definition.children) not in (3, 4):
            # This should only happen for the "Management::LOG" stream, for which the Zeek authors write:
            #   "Defining the stream outside of the stream creation call sidesteps the coverage.find-bro-logs test"
            # So it seems we should not try to find it anyway.
            print(f"Could not parse '{self.text(node)}' statement: could not find required attribute definitions ($columns, $path).", file=sys.stderr)
            return None

        # stream_definition.children:
        #   >=8.0: ['Log::Stream', '(', '$columns=Info, $ev=log_pe, $path="pe", $policy=log_policy', ')']
        #   < 8.0: ['[', '$columns=Info, $ev=log_pe, $path="pe", $policy=log_policy', ']']
        stream_info = stream_definition.children[-2]
        stream_id = normalize_identifier_with_namespace(self.text(id_node), namespace)
        stream_attr = {}

        for attr_node in stream_info.children:
            if attr_node.name() == 'expr':
                attr_name, attr_value = self.text(attr_node).split('=', maxsplit=1)
                stream_attr[attr_name.strip().lstrip('$')] = attr_value.strip(' "')

        if 'columns' not in stream_attr:
            raise ParseError(f"Unable to extract $columns from '{self.text(node)}'")

        if 'path' not in stream_attr or not stream_attr['path']:
            # Default to module name
            print(f"Warning: no $path in '{self.text(node)}' definition.", sys.stderr)
            stream_attr['path'] = str(namespace)

        # Normalize $columns value with namespace
        stream_attr['columns'] = normalize_identifier_with_namespace(stream_attr['columns'], namespace)

        # Add current file to metadata
        stream_meta = {
            'filename': self.file
        }

        stream_definition = LogStream(id=stream_id, meta=stream_meta, columns=stream_attr['columns'], path=stream_attr['path'])
        return stream_definition

    def get_comment_for(self, node: Node, comment_type='zeekygen_next_comment') -> str | None:
        """
        Make sure that include_cst=True, else comment nodes are excluded.
        
        :param node: Node whose comment/description to find 
        :param comment_type: Either 'zeekygen_next_comment', 'zeekygen_prev_comment' or 'minor_comment'
        :return: parsed and formatted comment / description
        """
        sibling_nodes = node.next_cst_siblings if comment_type == 'zeekygen_prev_comment' else node.prev_cst_siblings

        # TODO: check and probably fix the zeekygen_prev_comment

        if zeekygen_nodes := tuple(filter(lambda s: s.name() == comment_type, sibling_nodes)):
            # TODO: perhaps some markdown formatting here

            # Format comment and glue lines together
            return '\n'.join(
                self.text(n).lstrip('#').strip()
                for n in zeekygen_nodes
            )

        return None

    def get_type_name(self, type_node: Node, namespace: str = 'global') -> tuple[str, str | tuple[str, ...] | None]:

        if type_node.type == 'id':
            return LazyIdentifier(normalize_identifier_with_namespace(self.text(type_node), namespace)), None

        # Get 'type' of the node with the type information
        # For primitive types, this is also the name of the type
        type_name = type_node.children[0].type

        # For identifiers, however, the type is 'id' and we need to retrieve and properly namespace the name
        # We wrap the type name in a LazyIdentifier, so we can substitute it later with the actual definition
        if type_name == 'id':
            return LazyIdentifier(normalize_identifier_with_namespace(self.text(type_node), namespace)), None

        # Get nested type name (if any)
        nested_types = None
        match type_name:
            case 'set':  # "set" "[" "list($.type, ...)" "]"
                nested_types = tuple(
                    self.get_type_name(t, namespace) for t in type_node.children[2:-1]
                    if t.is_named  # Skip tokens (',' in this case)
                )

                if len(nested_types) == 1:
                    nested_types = nested_types[0]

            case 'vector' | 'list':  # "vector|list|file|opaque" "of" "$.type"
                nested_types = self.get_type_name(type_node.children[2], namespace)

            case 'table':  # "table" "[" "list($.type, ...)" "]" "of" "$.type"
                # TODO: we skip the type of the keys, decide if that's indeed desired behavior
                nested_types = self.get_type_name(type_node.children[-1], namespace)

            case 'file' | 'opaque' | 'table' | 'union':

                # "union" "{" "list($.type, ...)" "}"
                # TODO: implement someday
                pass

        if isinstance(nested_types, tuple) and len(nested_types) == 2 and nested_types[1] is None:
            nested_types = nested_types[0]

        return type_name, nested_types

    ##
    # Static methods
    ##

    @staticmethod
    def read_zeekscript(path_or_buffer: Path | BytesIO) -> Script:
        # Parse zeekscript file
        script = Script(path_or_buffer)

        # Parse source and handle any errors
        if not script.parse():
            _error = script.get_error()

            # Ignore some errors

            if _error[0].startswith('@pragma'):
                pass
            elif 'gsub(gsub(clean(v)' in _error[0]:
                # Weird irrelevant error in 2.6/scripts/base/utils/json.bro
                pass
            elif _error[0].startswith('@deprecated="Remove in 3.1.  to_json is now always available as a built-in function."'):
                # Another irrelevant error in 3.0/scripts/base/utils/json.zeek (repeat offender)
                pass
            elif (_error[0].startswith('event ssl_server_hello(c: connection, version: count, record_version: count, possible_ts: time')
                  or _error[0].startswith('event ssl_client_hello(c: connection, version: count, record_version: count, possible_ts: time')):
                # SalesForce JA3 plugin uses a version check with @if statements that causes this error, which we handle later on.
                pass
            else:  # Raise on others
                script_name = path_or_buffer if isinstance(path_or_buffer, Path) else "(custom script or package)"
                raise ParseError(f"Script \"{script_name}\" has error: \"{_error}\"")

        # Return parsed script
        return script


def merge_redefs(record_declaration: RecordDeclaration | None, redefs: list[RecordDeclaration] | None):
    if not record_declaration and not redefs:
        raise ValueError("No record declarations provided to merge.")

    # If there are no redefinitions, just return the original
    if not redefs:
        return record_declaration

    if not record_declaration:
        raise ValueError("No record declaration provided.")

    # Merge redefinitions
    record_declaration.meta['redefined_in'] = []

    for redef in redefs:
        # Merge fields
        record_declaration.fields.extend(redef.fields)

        # Merge metadata
        record_declaration.meta['redefined_in'].append(redef.meta['filename'])

    return record_declaration


def process_zeek_source(files: Iterable[Path | MemoryFile] | Generator[Path | MemoryFile, None, None]) -> tuple[
    dict[str, LogStream],
    dict[str, RecordDeclaration]
]:
    """
    Process ZeekScript files and extract record and log stream definitions.

    @param files: List of .bro|.zeek files to process.
    @return:
    """

    record_declarations: dict[str, RecordDeclaration] = {}
    record_redefs: defaultdict[str, list[RecordDeclaration]] = defaultdict(list)

    # Preload with internally defined, default types (https://docs.zeek.org/en/master/scripts/base/bif/types.bif.zeek.html)
    other_types: dict[str, str] = {
        'mount3::auth_flavor_t': 'enum',
        'mount3::proc_t': 'enum',
        'mount3::status_t': 'enum',
        'nfs3::createmode_t': 'enum',
        'nfs3::file_type_t': 'enum',
        'nfs3::proc_t': 'enum',
        'nfs3::stable_how_t': 'enum',
        'nfs3::status_t': 'enum',
        'nfs3::time_how_t': 'enum',
        'reporter::level': 'enum',
        'global::tablechange': 'enum',
        'tunnel::type': 'enum',
        'global::layer3_proto': 'enum',
        'global::link_encap': 'enum',
        'global::rpc_status': 'enum',
        'redis::rediscommand': 'enum',
    }

    stream_definitions: list[LogStream] = []

    # Process all ZeekScript files, extract record declarations and log stream definitions
    for file in files:

        # Skip documentation examples
        if 'broxygen/example' in str(file) or 'zeekygen/example' in str(file):
            continue

        parser = ZeekScriptParser(file)
        results = parser.parse()

        # Store results
        for r in results.get('records', []):
            if r.is_redef:
                record_redefs[r.name].append(r)
            else:
                record_declarations[r.name] = r

        if results.get('types', None):
            other_types |= results['types']

        if results.get('streams', None):
            stream_definitions.extend(results['streams'])

    # Post-processing

    # NOTE: in the current state of this script, there are redef's that have no original declaration. This is because we mix up the namespace if global records
    # are redefined inside another module. We do not keep global records of everything that has already been defined at the point a particular module is loaded,
    # so purely by (basic) static analysis it is impossible to correlate those.
    # In practice, luckily, this happens only for records 'connection' and 'fa_file', both of which are irrelevant for output logging purposes.
    # We therefore use the original declaration list (`record_declarations`) as ground truth, and accept the fact that we miss some records.

    # Merge redefs into their original declaration
    records = {
        record_name: merge_redefs(
            record_declarations[record_name],
            record_redefs.get(record_name, [])
        )
        for record_name in record_declarations
    }

    # Determine which records and other types are in use: i.e. those directly used in create_stream expressions or nested in those records.
    # Currently, mostly for debugging purposes, but this could come in handy later for analysis.
    records_in_use: set[str] = set(s.columns for s in stream_definitions)
    types_in_use: set[str] = set()

    def recursive_replace_lazy_identifiers(rd: RecordDeclaration):
        for f in rd.fields:
            if isinstance(f.type, LazyIdentifier):

                # Replace the LazyIdentifier type with its actual declaration.
                # Then, we can later normalize them (i.e. convert the `conn_id` 5-tuple to `id.orig_h`, `id.orig_p`, etc.)
                type_decl = _lookup_lazy_identifier(f.type)

                if isinstance(type_decl, tuple):
                    f.type = type_decl[0]
                    # Also lookup nested types
                    f.nested_type = _lookup_lazy_identifier(type_decl[1])
                else:
                    f.type = type_decl

            elif isinstance(f.nested_type, LazyIdentifier):
                f.nested_type = _lookup_lazy_identifier(f.nested_type)

        return rd

    def _lookup_lazy_identifier(lazy_id: LazyIdentifier | str) -> str | RecordDeclaration:
        """
        For other types. Can probably be merged with above function.
        :return:
        """
        if not isinstance(lazy_id, LazyIdentifier):
            return lazy_id

        local_type = str(lazy_id)
        global_type = f"global::{lazy_id.rsplit('::', maxsplit=1)[1]}"

        # First lookup either record or other type declaration by the provided type name
        # If found, recursively process the nested record as well
        if local_type in records:
            type_decl = recursive_replace_lazy_identifiers(records[local_type])
            records_in_use.add(local_type)

        elif local_type in other_types:
            type_decl = other_types[local_type]
            types_in_use.add(local_type)

        # Else, try and look it up in the global namespace
        elif global_type in records:
            type_decl = recursive_replace_lazy_identifiers(records[global_type])
            records_in_use.add(global_type)

        elif global_type in other_types:
            type_decl = other_types[global_type]
            types_in_use.add(global_type)

        else:
            raise ValueError(f"While trying to replace identifier ({lazy_id}), no suitable record declaration was found in both its own and the global namespace.")

        return type_decl

    # Add a copy of the relevant record declaration to streams, but remove fields that are not logged
    for s in stream_definitions:

        if s.columns not in records:
            raise ValueError(f"Record {s.columns} is used in an output stream, but has no corresponding record declaration.")

        # Replace LazyIdentifier types with their respective record or other type declaration
        s.record = recursive_replace_lazy_identifiers(
            deepcopy(records[s.columns])
        )

        # Filter fields that are not logged
        s.record.filter_fields(lambda field: field.is_logged or isinstance(field.type, RecordDeclaration) and field.type.is_logged, recursive=True)

        # Flatten nested fields, so for example single field "id" (conn_id) expands to id.orig_h, id.orig_p, etc.
        s.record.expand_nested_fields()

    # Create subset of records that are used in log streams to return to the user
    record_index = {
        record_name: r
        for record_name, r in records.items()
        if record_name in set(s.columns for s in stream_definitions)
    }

    # Index streams by path
    stream_index = {s.path: s for s in stream_definitions}

    return stream_index, record_index


if __name__ == "__main__":
    # Smoke test

    # Path to Zeek source code to analyze
    # $ git clone https://github.com/zeek/zeek.git /tmp/zeek
    base_path = Path('/tmp/zeek')

    # Analyze (look for .bro or .zeek files)
    result = process_zeek_source(
        chain(
            base_path.glob('**/*.bro'),
            base_path.glob('**/*.zeek')
        )
    )

    print(result)
