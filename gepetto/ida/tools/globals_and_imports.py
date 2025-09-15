import json

import ida_kernwin
import ida_nalt
import ida_name
import idaapi
import idautils
import ida_typeinf
import ida_bytes
import idc

from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import (
    parse_ea, run_on_main_thread, parse_type_declaration, get_candidates_for_name,
    ea_to_hex, touch_last_ea, enumerate_symbols
)


def handle_list_globals_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        offset = int(args.get("offset", 0) or 0)
        count = int(args.get("count", 0) or 0)
        result = list_globals(offset, count)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_list_globals_filter_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = list_globals_filter(int(args.get("offset", 0) or 0), int(args.get("count", 0) or 0), args.get("filter", ""))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_list_imports_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = list_imports(int(args.get("offset", 0) or 0), int(args.get("count", 0) or 0))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_rename_global_variable_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = rename_global_variable(args.get("old_name"), args.get("new_name"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_set_global_variable_type_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = set_global_variable_type(args.get("variable_name"), args.get("new_type"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_global_variable_value_by_name_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = {"ok": True, "value": get_global_variable_value_by_name(args.get("variable_name"))}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_global_variable_value_at_address_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        ea = parse_ea(args.get("ea"))
        result = {"ok": True, "value": get_global_variable_value_internal(ea)}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


# ----------------------------------------------------------------------------

def list_globals(offset: int, count: int) -> dict:
    """
    List global symbols with pagination. Returns EAs as integers.

    Delegates enumeration to ida9_utils.enumerate_symbols() to ensure main-thread execution.
    """
    try:
        syms = enumerate_symbols()
        globals_list = [{"name": s["name"], "ea": int(s["ea"])} for s in syms if s.get("kind") == "global"]

        total = len(globals_list)
        actual_count = total if count == 0 else count
        next_offset = offset + actual_count
        if next_offset >= total:
            next_offset = None

        return {"ok": True, "data": globals_list[offset: offset + actual_count], "next_offset": next_offset}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def list_globals_filter(offset: int, count: int, flt: str) -> dict:
    res = list_globals(0, 0)["data"]
    if flt:
        fl = flt.lower()
        res = [g for g in res if fl in g["name"].lower()]
    if count == 0:
        count = len(res)
    next_offset = offset + count
    if next_offset >= len(res):
        next_offset = None
    return {"ok": True, "data": res[offset: offset + count], "next_offset": next_offset}


def list_imports(offset: int, count: int) -> dict:
    # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
    out = {"ok": False}
    
    def _do():
        try:
            nimps = ida_nalt.get_import_module_qty()
            rv = []
            for i in range(nimps):
                module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

                def imp_cb(ea, symbol_name, ordinal, acc):
                    symbol = symbol_name or f"#{ordinal}"
                    acc.append({"address": hex(ea), "imported_name": symbol, "module": module_name})
                    return True

                ida_nalt.enum_import_names(i, lambda ea, s, o: imp_cb(ea, s, o, rv))

            if count == 0:
                actual_count = len(rv)
            else:
                actual_count = count
            next_offset = offset + actual_count
            if next_offset >= len(rv):
                next_offset = None
            out.update({"ok": True, "data": rv[offset: offset + actual_count], "next_offset": next_offset})
            return 1
        except Exception as e:
            out.update({"error": str(e)})
            return 0
    
    run_on_main_thread(_do, write=False)
    return out


def rename_global_variable(old_name: str, new_name: str) -> dict:
    if not old_name:
        return {"ok": False, "error": "old_name is required"}
    if new_name is None:
        new_name = ""
    
    try:
        out = {"ok": False}

        def _do():
            try:
                # Resolve the name using ida_name.get_name_ea first
                ea = ida_name.get_name_ea(idaapi.BADADDR, old_name)
                if ea == idaapi.BADADDR:
                    # Fallback method
                    ea = idc.get_name_ea_simple(old_name)

                if ea == idaapi.BADADDR:
                    # Name not found, provide candidates
                    candidates = get_candidates_for_name(old_name, max_candidates=5)
                    if candidates:
                        out.update(
                            error=f"Global '{old_name}' not found",
                            candidates=candidates
                        )
                    else:
                        out.update(error=f"Global '{old_name}' not found")
                    return 0
                
                touch_last_ea(ea)
                
                # Use appropriate flags for renaming - SN_CHECK for validation, SN_FORCE if needed
                flags = idaapi.SN_CHECK
                if not idaapi.set_name(ea, new_name, flags):
                    # Try with force flag if initial attempt fails
                    flags = idaapi.SN_CHECK | idaapi.SN_FORCE
                    if not idaapi.set_name(ea, new_name, flags):
                        out.update(error=f"Failed to rename '{old_name}' to '{new_name}' (name may be invalid or protected)")
                        return 0
                        
                out.update(ok=True, address=ea_to_hex(ea), old_name=old_name, new_name=new_name)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for name changes
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Global variable rename failed: {str(e)}"}


def set_global_variable_type(variable_name: str, new_type: str) -> dict:
    if not variable_name or not new_type:
        return {"ok": False, "error": "variable_name and new_type are required"}
    
    try:
        out = {"ok": False}

        def _do():
            try:
                # Resolve the name using ida_name.get_name_ea first
                ea = ida_name.get_name_ea(idaapi.BADADDR, variable_name)
                if ea == idaapi.BADADDR:
                    # Fallback method
                    ea = idc.get_name_ea_simple(variable_name)
                    
                if ea == idaapi.BADADDR:
                    # Name not found, provide candidates
                    candidates = get_candidates_for_name(variable_name, max_candidates=5)
                    if candidates:
                        out.update(
                            error=f"Global '{variable_name}' not found",
                            candidates=candidates
                        )
                    else:
                        out.update(error=f"Global '{variable_name}' not found")
                    return 0
                
                touch_last_ea(ea)
                
                # Parse the type declaration using our utility
                try:
                    tif = parse_type_declaration(new_type)
                except ValueError as e:
                    out.update(error=str(e))
                    return 0
                
                # Apply type using IDA 9.x API via ida_nalt.set_tinfo
                if not ida_nalt.set_tinfo(ea, tif):
                    out.update(error=f"Failed to apply type '{new_type}' to '{variable_name}' (type may be incompatible with location)")
                    return 0
                    
                out.update(ok=True, address=ea_to_hex(ea), variable_name=variable_name, new_type=str(tif))
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Execute on main thread with write access for type modifications
        if not run_on_main_thread(_do, write=True):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Global variable type setting failed: {str(e)}"}


def get_global_variable_value_by_name(variable_name: str) -> str:
    try:
        # Run on UI thread for better compatibility
        result = {"value": None, "error": None}
        
        def _do():
            try:
                ea = ida_name.get_name_ea(idaapi.BADADDR, variable_name)
                if ea == idaapi.BADADDR:
                    result["error"] = f"Global variable {variable_name} not found"
                    return 0
                result["value"] = get_global_variable_value_internal(ea)
                return 1
            except Exception as e:
                result["error"] = str(e)
                return 0
        
        if not run_on_main_thread(_do, write=False):
            if result["error"]:
                raise ValueError(result["error"])
            raise ValueError(_("Failed to execute on main thread"))
        
        if result["error"]:
            raise ValueError(result["error"])
        return result["value"]
    except Exception as e:
        raise ValueError(_("Global variable value retrieval failed: {error}").format(error=str(e)))


def get_global_variable_value_internal(ea: int) -> str:
    # Enhanced error handling and thread safety
    touch_last_ea(ea)
    result = {"value": None, "error": None}
    
    def _do():
        try:
            tif = ida_typeinf.tinfo_t()
            size = 0
            
            # Try to get type info, with fallback handling
            try:
                if idaapi.get_tinfo(tif, ea):
                    size = tif.get_size()
                else:
                    # Fallback: try to get size from item
                    if idaapi.has_any_name(ea):
                        size = idaapi.get_item_size(ea)
                    else:
                        result["error"] = f"No type info or name found for address {ea:#x}"
                        return 0
            except Exception:
                # Last resort fallback
                try:
                    size = idaapi.get_item_size(ea)
                except Exception:
                    result["error"] = f"Failed to get size for address {ea:#x}"
                    return 0

            if size <= 0:
                result["error"] = f"Invalid size ({size}) for address {ea:#x}"
                return 0

            # Handle different data types with better error handling
            try:
                if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
                    try:
                        s = idaapi.get_strlit_contents(ea, -1, 0)
                        if s:
                            result["value"] = f"\"{s.decode('utf-8', errors='replace').strip()}\""
                        else:
                            result["value"] = '""'
                    except Exception:
                        result["value"] = "<string read error>"
                elif size == 1:
                    result["value"] = hex(ida_bytes.get_byte(ea))
                elif size == 2:
                    result["value"] = hex(ida_bytes.get_word(ea))
                elif size == 4:
                    result["value"] = hex(ida_bytes.get_dword(ea))
                elif size == 8:
                    result["value"] = hex(ida_bytes.get_qword(ea))
                else:
                    # For larger sizes, read bytes safely with size limit
                    max_size = min(size, 64)  # Limit to 64 bytes for safety
                    try:
                        data = ida_bytes.get_bytes(ea, max_size)
                        if data:
                            result["value"] = " ".join(f"{x:#02x}" for x in data)
                            if size > max_size:
                                result["value"] += " ..."
                        else:
                            result["value"] = "<read error>"
                    except Exception:
                        result["value"] = "<bytes read error>"
            except Exception as e:
                result["error"] = f"Data read error: {str(e)}"
                return 0
                
            return 1
        except Exception as e:
            result["error"] = str(e)
            return 0
        
    if not run_on_main_thread(_do, write=False):
        if result["error"]:
            raise ValueError(result["error"])
        raise ValueError(_("Failed to execute on main thread"))
    
    if result["error"]:
        raise ValueError(result["error"])
    return result["value"]

