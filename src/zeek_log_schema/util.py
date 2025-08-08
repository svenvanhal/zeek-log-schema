from zeekscript.node import Node


def first_child_with_name(node: Node, name: str) -> Node | None:
    try:
        matches = next(node.traverse(predicate=lambda n: n.name() == name))
        return matches[0]
    except StopIteration:
        return None


def normalize_identifier_with_namespace(name: str, namespace: str) -> str:
    if not name or not namespace:
        raise ValueError("Invalid name or namespace provided to normalize.")

    # Lowercase both name and namespace
    name, namespace = name.lower(), namespace.lower()

    # Check if the name is already prefixed with the namespace
    if name.startswith(f"{namespace}::"):
        return name

    # Ignore properly namespaced identifiers
    if "::" in name:
        return name

    # TODO: verify that this function works as expected

    return f"{namespace}::{name}"
