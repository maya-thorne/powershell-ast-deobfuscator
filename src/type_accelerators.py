"""
PowerShell Type Accelerators and Type Casting Definition Registry.
Maps shorthand PowerShell type accelerators to .NET type definitions.
"""

from typing import Any, Dict, Optional, Tuple


# Standard PowerShell type accelerators mapping alias -> Full .NET Type Name
TYPE_ACCELERATORS: Dict[str, str] = {
    # Fundamental primitives
    "bool": "System.Boolean",
    "boolean": "System.Boolean",
    "byte": "System.Byte",
    "sbyte": "System.SByte",
    "char": "System.Char",
    "decimal": "System.Decimal",
    "double": "System.Double",
    "float": "System.Single",
    "single": "System.Single",
    "int": "System.Int32",
    "int32": "System.Int32",
    "int64": "System.Int64",
    "long": "System.Int64",
    "uint": "System.UInt32",
    "uint32": "System.UInt32",
    "uint64": "System.UInt64",
    "ulong": "System.UInt64",
    "short": "System.Int16",
    "int16": "System.Int16",
    "ushort": "System.UInt16",
    "uint16": "System.UInt16",
    "string": "System.String",
    "void": "System.Void",

    # Arrays
    "byte[]": "System.Byte[]",
    "char[]": "System.Char[]",
    "int[]": "System.Int32[]",
    "string[]": "System.String[]",
    "object[]": "System.Object[]",
    "array": "System.Array",

    # Common .NET namespaces & utilities
    "type": "System.Type",
    "convert": "System.Convert",
    "math": "System.Math",
    "regex": "System.Text.RegularExpressions.Regex",
    "datetime": "System.DateTime",
    "timespan": "System.TimeSpan",
    "guid": "System.Guid",
    "uri": "System.Uri",
    "version": "System.Version",

    # Text & IO
    "encoding": "System.Text.Encoding",
    "text.encoding": "System.Text.Encoding",
    "system.text.encoding": "System.Text.Encoding",

    # Collections
    "hashtable": "System.Collections.Hashtable",
    "arraylist": "System.Collections.ArrayList",
    "list": "System.Collections.Generic.List`1",

    # PowerShell specific
    "psobject": "System.Management.Automation.PSObject",
    "scriptblock": "System.Management.Automation.ScriptBlock",
    "switch": "System.Management.Automation.SwitchParameter",
    "xml": "System.Xml.XmlDocument",
}

# Preferred canonical shorthand alias for each .NET full name
CANONICAL_ALIASES: Dict[str, str] = {
    "System.Boolean": "bool",
    "System.Byte": "byte",
    "System.SByte": "sbyte",
    "System.Char": "char",
    "System.Decimal": "decimal",
    "System.Double": "double",
    "System.Single": "float",
    "System.Int32": "int",
    "System.Int64": "long",
    "System.Int16": "short",
    "System.UInt32": "uint",
    "System.UInt64": "ulong",
    "System.UInt16": "ushort",
    "System.String": "string",
    "System.Void": "void",
    "System.Byte[]": "byte[]",
    "System.Char[]": "char[]",
    "System.Int32[]": "int[]",
    "System.String[]": "string[]",
    "System.Array": "array",
    "System.Type": "type",
    "System.Convert": "convert",
    "System.Math": "math",
    "System.Text.RegularExpressions.Regex": "regex",
    "System.Text.Encoding": "System.Text.Encoding",
    "System.DateTime": "datetime",
    "System.Guid": "guid",
    "System.Management.Automation.PSObject": "psobject",
    "System.Management.Automation.ScriptBlock": "scriptblock",
    "System.Xml.XmlDocument": "xml",
}


class TypeAcceleratorRegistry:
    """
    Registry for resolving, normalizing, and reflecting PowerShell type accelerators.
    """

    @staticmethod
    def clean_name(raw_name: str) -> str:
        """Strips surrounding brackets, whitespace, and leading colons."""
        cleaned = raw_name.strip()
        while cleaned.startswith("[") and cleaned.endswith("]"):
            cleaned = cleaned[1:-1].strip()
        return cleaned

    @classmethod
    def is_type_accelerator(cls, name: str) -> bool:
        cleaned = cls.clean_name(name).lower()
        return cleaned in TYPE_ACCELERATORS

    @classmethod
    def resolve_full_type(cls, name: str) -> str:
        """
        Resolves a shorthand accelerator or partial name to its full .NET type name.
        e.g., 'char[]' -> 'System.Char[]', 'System.String' -> 'System.String'
        """
        cleaned = cls.clean_name(name)
        lower_key = cleaned.lower()
        if lower_key in TYPE_ACCELERATORS:
            return TYPE_ACCELERATORS[lower_key]
        return cleaned

    @classmethod
    def get_canonical_alias(cls, name: str) -> str:
        """
        Returns the canonical short accelerator or cleanest representation.
        e.g., 'System.Char[]' -> 'char[]', 'cHaR' -> 'char'
        """
        full_name = cls.resolve_full_type(name)
        if full_name in CANONICAL_ALIASES:
            return CANONICAL_ALIASES[full_name]
        return full_name

    @classmethod
    def get_type_metadata(cls, name: str) -> Dict[str, str]:
        """
        Returns reflection metadata simulating .NET System.Type properties:
        Name, FullName, Namespace, AssemblyQualifiedName.
        """
        full_name = cls.resolve_full_type(name)
        if "." in full_name:
            namespace, type_name = full_name.rsplit(".", 1)
        else:
            namespace, type_name = "", full_name

        return {
            "Name": type_name,
            "FullName": full_name,
            "Namespace": namespace,
            "Assembly": "mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
        }
