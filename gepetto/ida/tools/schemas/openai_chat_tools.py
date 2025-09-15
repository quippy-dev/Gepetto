# flake8: noqa
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_screen_ea",
            "description": "Return the current effective address (EA).",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_strings_filter",
            "description": "List matching strings (paginated) using a case-insensitive filter or /regex/.",
            "parameters": {
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "description": "Start index (0-based)."},
                    "count": {"type": "integer", "description": "Number to return (0 = remainder)."},
                    "filter": {"type": "string", "description": "Substring or /regex/ to match against string text."}
                },
                "required": ["offset", "count", "filter"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_ea",
            "description": "Return EA for a symbol name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Symbol or function name.",
                    },
                },
                "required": ["name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "to_hex",
            "description": "Convert a decimal integer to a hexadecimal string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "integer",
                        "description": "Decimal integer to convert.",
                    },
                },
                "required": ["value"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_disasm",
            "description": "Return disassembly for an effective address.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address to disassemble.",
                    },
                },
                "required": ["ea"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_bytes",
            "description": "Return raw bytes for an effective address (default size = 0x20).",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address to read from.",
                    },
                    "size": {
                        "type": "integer",
                        "description": "Number of bytes to read (optional)."
                    }
                },
                "required": ["ea"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_code",
            "description": "Return Hex-Rays pseudocode for the function that contains the given EA.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "EA inside the target function (decimal or hex)."
                    },
                },
                "required": ["ea"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_lvar",
            "description": "Rename a local variable within a function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address (EA) inside the target function, in either decimal or hex.",
                    },
                    "old_name": {
                        "type": "string",
                        "description": "Current local variable name to be changed.",
                    },
                    "new_name": {
                        "type": "string",
                        "description": "Desired new name for the local variable.",
                    },
                },
                "required": ["ea", "old_name", "new_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_function",
            "description": "Rename a function. Use a unique, valid identifier; IDA may adjust invalid names.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {
                        "type": "integer",
                        "description": "Effective address (EA) inside the target function, in either decimal or hex.",
                    },
                    "new_name": {
                        "type": "string",
                        "description": "Desired new name for the function.",
                    },
                },
                "required": ["ea", "new_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_xrefs",
            "description": (
                "Return cross-references (code/data) for an address, a whole function, "
                "or a named symbol. Supports incoming, outgoing, or both directions, "
                "with practical filters (only_code/only_calls/exclude_flow) and "
                "deduping (collapse_by)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "description": "Scope of the query: single EA, the whole function, or a name.",
                        "enum": ["ea", "function", "name"]
                    },
                    "subject": {
                        "type": "string",
                        "description": (
                            "Subject to inspect. If scope=='ea' or 'function', this may be an EA "
                            "as decimal or hex string ('0x401000', '401000h'). "
                            "If scope=='name', this must be a symbol name."
                        )
                    }
                },
                "required": ["scope", "subject"],
                "additionalProperties": False
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_symbols",
            "description": (
                "Return names and EAs for functions, optionally including globals. "
                "Supports prefix filtering."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "prefix": {"type": "string", "description": "Only names starting with this prefix."},
                    "include_globals": {"type": "boolean", "description": "Include non-function symbols (default false)."}
                },
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search",
            "description": "Search for text or hex byte patterns. Provide exactly one of 'text' or 'hex'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to search (ASCII/Unicode)."},
                    "hex": {"type": "string", "description": "Hex pattern (e.g., '90 90 ?? 55')."},
                    "case_sensitive": {"type": "boolean", "description": "Case-sensitive text search (default false)."}
                },
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_strings",
            "description": "Enumerate discovered strings with pagination and filters.",
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max items to return (default 200)."},
                    "offset": {"type": "integer", "description": "Start index (default 0)."},
                    "min_len": {"type": "integer", "description": "Minimum string length (default 4)."},
                    "encodings": {"type": "array", "items": {"type": "string"}, "description": "Subset, e.g., ['ascii','utf16']."},
                    "segments": {"type": "array", "items": {"type": "string"}, "description": "Segment names to include."},
                    "include_xrefs": {"type": "boolean", "description": "Also return xrefs to each string."},
                    "include_text": {"type": "boolean", "description": "Include (clipped) string text."},
                    "max_text_bytes": {"type": "integer", "description": "Clip text to at most N bytes (default 256)."},
                    "return_addresses_only": {"type": "boolean", "description": "Return only EAs instead of metadata."},
                    "sort_by": {"type": "string", "enum": ["ea", "len", "segment"], "description": "Sort key (default 'ea')."}
                },
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callers",
            "description": "Return the unique caller functions of a target function (by EA or name).",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {"type": "integer", "description": "EA inside the target function."}
                },
                "required": ["ea"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_callees",
            "description": "Return the unique callee functions reached from the target function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ea": {"type": "integer"}
                },
                "required": ["ea"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "refresh_view",
            "description": "Refresh the current IDA disassembly view to show recent changes.",
            "parameters": {
                "type": "object",
                "properties": {},
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_metadata",
            "description": "Return IDB metadata: input path, module name, image base/size, hashes.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_user_input_sites",
            "description": (
                "Find call sites to common user-input APIs (e.g., gets/fgets/scanf, std::getline, ReadFile). "
                "Useful to locate password-entry points."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "names": {"type": "array", "items": {"type": "string"}, "description": "Optional list of API name substrings to search for."}
                },
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_calls_to",
            "description": "Find call sites to any symbol whose name contains the given substring.",
            "parameters": {
                "type": "object",
                "properties": {"name_filter": {"type": "string", "description": "Substring of callee name (case-insensitive)."}},
                "required": ["name_filter"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "declare_c_type",
            "description": "Create or update a local type from a C declaration (typedef/struct).",
            "parameters": {
                "type": "object",
                "properties": {
                    "c_declaration": {"type": "string", "description": "C declaration for type/struct/typedef."}
                },
                "required": ["c_declaration"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_by_name",
            "description": "Lookup a function by name and return its address and size.",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string", "description": "Function name (demangled ok)."}},
                "required": ["name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_by_address",
            "description": "Return function info for a given address.",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string", "description": "EA (e.g., 0x401000)."}},
                "required": ["address"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_immediates",
            "description": "List immediate constants used by instructions in a function.",
            "parameters": {"type": "object", "properties": {"function_address": {"type": "string"}}, "required": ["function_address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_function_strings",
            "description": "List strings referenced by a function.",
            "parameters": {"type": "object", "properties": {"function_address": {"type": "string"}}, "required": ["function_address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_current_address",
            "description": "Return the current EA as a hex string. May return 'BADADDR' if no view is focused.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_current_function",
            "description": "Return info about the function at the current EA.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decompile_function",
            "description": "Decompile a function at the given address and return pseudocode.",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Address of the function to decompile (e.g., 0x401000)."}
                },
                "required": ["address"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "convert_number",
            "description": "Convert a number string to decimal/hex/bytes/ascii/binary forms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Number text (e.g., 123, 0x7B)."},
                    "size": {"type": "integer", "description": "Optional byte size for conversion."}
                },
                "required": ["text"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_functions",
            "description": "List functions with pagination.",
            "parameters": {
                "type": "object",
                "properties": {
                    "offset": {"type": "integer", "description": "Start index (0-based)."},
                    "count": {"type": "integer", "description": "Number to return (0 = all)."}
                },
                "required": ["offset", "count"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_globals",
            "description": "List globals with pagination. Use list_globals_filter for filtering.",
            "parameters": {
                "type": "object",
                "properties": {
                    "offset": {"type": "integer"},
                    "count": {"type": "integer"}
                },
                "required": ["offset", "count"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_globals_filter",
            "description": "List globals filtered by substring (case-insensitive).",
            "parameters": {
                "type": "object",
                "properties": {
                    "offset": {"type": "integer"},
                    "count": {"type": "integer"},
                    "filter": {"type": "string", "description": "Filter (empty for none)."}
                },
                "required": ["offset", "count", "filter"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_imports",
            "description": "List imported symbols with module names (paginated).",
            "parameters": {
                "type": "object",
                "properties": {"offset": {"type": "integer"}, "count": {"type": "integer"}},
                "required": ["offset", "count"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_local_types",
            "description": "List defined local types with C declarations where possible.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "disassemble_function",
            "description": "Return structured disassembly for a function (lines, labels, comments).",
            "parameters": {
                "type": "object",
                "properties": {"start_address": {"type": "string", "description": "Function start EA."}},
                "required": ["start_address"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_xrefs_to",
            "description": "Get cross-references to an address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_xrefs_to_field",
            "description": "Get references to a struct field (struct + field name).",
            "parameters": {
                "type": "object",
                "properties": {"struct_name": {"type": "string"}, "field_name": {"type": "string"}},
                "required": ["struct_name", "field_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_entry_points",
            "description": "List entry-point functions for the binary.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_comment",
            "description": "Set a disassembly and (if possible) pseudocode comment at an address.",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}, "comment": {"type": "string"}},
                "required": ["address", "comment"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_local_variable",
            "description": "Rename a local variable in a function (address + old/new names).",
            "parameters": {
                "type": "object",
                "properties": {"function_address": {"type": "string"}, "old_name": {"type": "string"}, "new_name": {"type": "string"}},
                "required": ["function_address", "old_name", "new_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_global_variable",
            "description": "Rename a global variable by name.",
            "parameters": {"type": "object", "properties": {"old_name": {"type": "string"}, "new_name": {"type": "string"}}, "required": ["old_name", "new_name"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_function_prototype",
            "description": "Apply a new function prototype to a function start address.",
            "parameters": {"type": "object", "properties": {"function_address": {"type": "string"}, "prototype": {"type": "string"}}, "required": ["function_address", "prototype"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_local_variable_type",
            "description": (
                "Set a local (stack frame) variable's type. "
                "Call get_stack_frame_variables first to discover the exact variable_name. "
                "Examples: new_type='int', 'char[16]', 'int32_t' (after declare_c_type). "
                "Writes to the database; do not parallelize."
            ),
            "parameters": {"type": "object", "properties": {"function_address": {"type": "string"}, "variable_name": {"type": "string"}, "new_type": {"type": "string"}}, "required": ["function_address", "variable_name", "new_type"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_stack_frame_variables",
            "description": "List stack frame variables with offsets/types for a function.",
            "parameters": {"type": "object", "properties": {"function_address": {"type": "string"}}, "required": ["function_address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "rename_stack_frame_variable",
            "description": (
                "Rename a local (stack) variable by its current frame name. "
                "Arguments in the frame cannot be renamed. Writes to the database; do not parallelize."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_address": {"type": "string"},
                    "old_name": {"type": "string"},
                    "new_name": {"type": "string"},
                },
                "required": ["function_address", "old_name", "new_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_stack_frame_variable",
            "description": (
                "Create a stack variable at the given frame offset (locals use negative offsets like -0x8). "
                "type_name may be any valid C type (e.g., 'int', 'char[32]', or a typedef declared via declare_c_type). "
                "Writes to the database; do not parallelize."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_address": {"type": "string"},
                    "offset": {"type": "string"},
                    "variable_name": {"type": "string"},
                    "type_name": {"type": "string"},
                },
                "required": ["function_address", "offset", "variable_name", "type_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_stack_frame_variable_type",
            "description": (
                "Set the type for an existing stack variable. "
                "Prefer this over set_local_variable_type when working with frame members. Writes to the database; do not parallelize."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_address": {"type": "string"},
                    "variable_name": {"type": "string"},
                    "type_name": {"type": "string"},
                },
                "required": ["function_address", "variable_name", "type_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_stack_frame_variable",
            "description": (
                "Delete a named stack (frame) variable. Arguments and special frame members cannot be deleted. "
                "Writes to the database; do not parallelize."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_address": {"type": "string"},
                    "variable_name": {"type": "string"},
                },
                "required": ["function_address", "variable_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_defined_structures",
            "description": "List all defined structures (name/size/members).",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_struct_detailed",
            "description": "Detailed analysis of a structure's fields.",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_struct_at_address",
            "description": "Read a structure's member values at an address.",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}, "struct_name": {"type": "string"}},
                "required": ["address", "struct_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_struct_info_simple",
            "description": "Basic structure info (size/members).",
            "parameters": {
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_structures",
            "description": "Search structures by name substring.",
            "parameters": {
                "type": "object",
                "properties": {"filter": {"type": "string"}},
                "required": ["filter"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_global_variable_value_by_name",
            "description": "Read a global variable value by name.",
            "parameters": {
                "type": "object",
                "properties": {"variable_name": {"type": "string"}},
                "required": ["variable_name"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_global_variable_value_at_address",
            "description": "Read a global variable value at address.",
            "parameters": {
                "type": "object",
                "properties": {"ea": {"type": "string"}},
                "required": ["ea"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "set_global_variable_type",
            "description": "Set a global variable's type.",
            "parameters": {
                "type": "object",
                "properties": {"variable_name": {"type": "string"}, "new_type": {"type": "string"}},
                "required": ["variable_name", "new_type"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_memory_bytes",
            "description": "Read raw bytes from memory.",
            "parameters": {
                "type": "object",
                "properties": {"memory_address": {"type": "string"}, "size": {"type": "integer"}},
                "required": ["memory_address", "size"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "data_read_byte",
            "description": "Read 1 byte at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "data_read_word",
            "description": "Read 2 bytes (word) at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "data_read_dword",
            "description": "Read 4 bytes (dword) at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "data_read_qword",
            "description": "Read 8 bytes (qword) at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "data_read_string",
            "description": "Read a string at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_address_assembles",
            "description": "Patch multiple instructions starting at address (semicolon-separated).",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}, "assembles": {"type": "string"}},
                "required": ["address", "assembles"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_nop_instructions",
            "description": (
                "Replace N instruction(s) starting at address with NOPs of equal total length. "
                "Writes to the database; do not parallelize."
            ),
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}, "count": {"type": "integer", "description": "Number of instructions (default 1)."}},
                "required": ["address"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_force_fallthrough",
            "description": (
                "Bypass a single conditional by NOPing one instruction at address (force fallthrough). "
                "Writes to the database; do not parallelize."
            ),
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_function",
            "description": (
                "Return a compact summary: function info, basic blocks, top callees (with counts), quick metrics, and a preview of strings/immediates. "
                "Set include_edges=true to also include CFG edges."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "function_address": {"type": "string"},
                    "include_edges": {"type": "boolean", "description": "Include CFG edges (default false)."},
                    "max_preview": {"type": "integer", "description": "Max preview items for strings/immediates (default 10)."},
                    "max_blocks": {"type": "integer", "description": "Cap number of basic blocks processed (default 512)."}
                },
                "required": ["function_address"],
                "additionalProperties": False
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "summarize_program",
            "description": "Program-level summary: entry points, categorized imports, and high-fan-in functions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "top_n": {"type": "integer", "description": "Top N results for high-fan-in (default 10)."},
                    "max_functions": {"type": "integer", "description": "Max functions to scan for fan-in (default 500)."}
                },
                "additionalProperties": False
            },
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_get_registers",
            "description": "UNSAFE: List registers per thread during debugging.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_get_call_stack",
            "description": "UNSAFE: Get current call stack frames.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_list_breakpoints",
            "description": "UNSAFE: List all breakpoints.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_start_process",
            "description": "UNSAFE: Start debugger.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_exit_process",
            "description": "UNSAFE: Exit debugger.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_continue_process",
            "description": "UNSAFE: Continue debugger execution.",
            "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_run_to",
            "description": "UNSAFE: Run to address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_set_breakpoint",
            "description": "UNSAFE: Set a breakpoint at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_delete_breakpoint",
            "description": "UNSAFE: Delete a breakpoint at address.",
            "parameters": {"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"], "additionalProperties": False},
            "strict": False,
        },
    },
    {
        "type": "function",
        "function": {
            "name": "dbg_enable_breakpoint",
            "description": "UNSAFE: Enable/disable breakpoint at address.",
            "parameters": {
                "type": "object",
                "properties": {"address": {"type": "string"}, "enable": {"type": "boolean"}},
                "required": ["address", "enable"],
                "additionalProperties": False,
            },
            "strict": False,
        },
    },
]
