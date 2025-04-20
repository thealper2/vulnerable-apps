from enum import Enum


class ParserType(str, Enum):
    """Enum for different XML parser types"""

    UNSAFE = "unsafe"
    DEFUSED = "defused"
    LXML = "lxml"
    ELEMENT_TREE = "element_tree"
    CUSTOM = "custom"
