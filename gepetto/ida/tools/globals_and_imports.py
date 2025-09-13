import json

import ida_kernwin
import ida_nalt
import ida_name
import ida_bytes
import idautils
import ida_typeinf

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


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
    items = []
    for addr, name in idautils.Names():
        if not idaapi.get_func(addr):
            items.append({"address": hex(addr), "name": name})
    if count == 0:
        count = len(items)
    next_offset = offset + count
    if next_offset >= len(items):
        next_offset = None
    return {"ok": True, "data": items[offset: offset + count], "next_offset": next_offset}


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
        count = len(rv)
    next_offset = offset + count
    if next_offset >= len(rv):
        next_offset = None
    return {"ok": True, "data": rv[offset: offset + count], "next_offset": next_offset}


def rename_global_variable(old_name: str, new_name: str) -> dict:
    if not old_name:
        raise ValueError("old_name is required")
    if new_name is None:
        new_name = ""
    out = {"ok": False}

    def _do():
        try:
            ea = ida_name.get_name_ea(idaapi.BADADDR, old_name)
            if ea == idaapi.BADADDR:
                out.update(error=f"Global {old_name} not found")
                return 0
            if not idaapi.set_name(ea, new_name):
                out.update(error=f"Failed to rename {old_name} -> {new_name}")
                return 0
            out.update(ok=True, address=hex(ea), old_name=old_name, new_name=new_name)
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)
    return out


def set_global_variable_type(variable_name: str, new_type: str) -> dict:
    if not variable_name or not new_type:
        raise ValueError("variable_name and new_type are required")
    out = {"ok": False}

    def _do():
        try:
            ea = ida_name.get_name_ea(idaapi.BADADDR, variable_name)
            if ea == idaapi.BADADDR:
                out.update(error=f"Global {variable_name} not found")
                return 0
            tif = ida_typeinf.tinfo_t(new_type) or ida_typeinf.tinfo_t()
            if not str(tif):  # naive check
                # try parse_decl fallback
                t2 = ida_typeinf.tinfo_t()
                ida_typeinf.parse_decl(t2, None, new_type + ";", ida_typeinf.PT_SIL)
                tif = t2
            if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL):
                out.update(error="Failed to apply type")
                return 0
            out.update(ok=True, address=hex(ea), variable_name=variable_name, new_type=str(tif))
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)
    return out


def get_global_variable_value_by_name(variable_name: str) -> str:
    ea = ida_name.get_name_ea(idaapi.BADADDR, variable_name)
    if ea == idaapi.BADADDR:
        raise ValueError(f"Global variable {variable_name} not found")
    return get_global_variable_value_internal(ea)


def get_global_variable_value_internal(ea: int) -> str:
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, ea):
        if not ida_bytes.has_any_name(ea):
            raise ValueError(f"Failed to get type info for {ea:#x}")
        size = ida_bytes.get_item_size(ea)
        if size == 0:
            raise ValueError(f"Failed to get type info for {ea:#x}")
    else:
        size = tif.get_size()

    if size == 0 and tif.is_array() and tif.get_array_element().is_decl_char():
        s = ida_bytes.get_strlit_contents(ea, -1, 0).decode("utf-8").strip()
        return f"\"{s}\""
    elif size == 1:
        return hex(ida_bytes.get_wide_byte(ea))
    elif size == 2:
        return hex(ida_bytes.get_wide_word(ea))
    elif size == 4:
        return hex(ida_bytes.get_wide_dword(ea))
    elif size == 8:
        return hex(ida_bytes.get_qword(ea))
    else:
        bs = ida_bytes.get_bytes(ea, size) or b""
        return " ".join(hex(x) for x in bs)
