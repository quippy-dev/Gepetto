import json

import ida_entry
import ida_kernwin
import ida_funcs
import ida_name
import idaapi

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_get_function_by_name_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    name = args.get("name") or ""
    try:
        result = get_function_by_name(name)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_function_by_address_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    address = args.get("address")
    try:
        result = get_function_by_address(address)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_current_address_tc(tc, messages):
    try:
        result = {"ok": True, "address": get_current_address()}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_current_function_tc(tc, messages):
    try:
        result = get_current_function()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_list_functions_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    offset = int(args.get("offset", 0) or 0)
    count = int(args.get("count", 0) or 0)
    try:
        result = list_functions(offset, count)
    except Exception as ex:
        result = {"ok": False, "error": str(ex), "offset": offset, "count": count}
    add_result_to_messages(messages, tc, result)


def handle_get_entry_points_tc(tc, messages):
    try:
        result = get_entry_points()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


# ----------------------------------------------------------------------------

def _func_info(fn: ida_funcs.func_t) -> dict:
    name = ida_funcs.get_func_name(fn.start_ea) or ida_name.get_ea_name(fn.start_ea) or ""
    return {"address": hex(fn.start_ea), "name": name, "size": hex(fn.end_ea - fn.start_ea)}


def get_function_by_name(name: str) -> dict:
    if not name:
        raise ValueError("name is required")
    out = {"ok": False}

    def _do():
        try:
            ea = ida_name.get_name_ea(idaapi.BADADDR, name)
            if ea == idaapi.BADADDR:
                # also try demangled map by scanning
                for f_ea in ida_funcs.Functions():
                    dem = idaapi.demangle_name(ida_name.get_name(f_ea), idaapi.MNG_NODEFINIT)
                    if dem and dem == name:
                        ea = f_ea
                        break
            if ea == idaapi.BADADDR:
                out.update(error=f"No function found with name {name}")
                return 0
            fn = ida_funcs.get_func(ea)
            if not fn:
                out.update(error=f"Symbol found but not inside a function: {name}")
                return 0
            out.update(ok=True, **_func_info(fn))
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out


def get_function_by_address(address: str) -> dict:
    ea = parse_ea(address)
    out = {"ok": False}

    def _do():
        try:
            fn = ida_funcs.get_func(ea)
            if not fn:
                out.update(error=f"No function found at {hex(ea)}")
                return 0
            out.update(ok=True, **_func_info(fn))
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out


def get_current_address() -> str:
    return hex(idaapi.get_screen_ea())


def get_current_function() -> dict:
    out = {"ok": False}

    def _do():
        try:
            ea = idaapi.get_screen_ea()
            fn = ida_funcs.get_func(ea)
            if not fn:
                out.update(error="No function at current EA")
                return 0
            out.update(ok=True, **_func_info(fn))
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    return out


def list_functions(offset: int, count: int) -> dict:
    funcs = list(ida_funcs.Functions())
    items = [
        _func_info(ida_funcs.get_func(ea)) for ea in funcs
        if ida_funcs.get_func(ea) is not None
    ]
    if count == 0:
        count = len(items)
    next_offset = offset + count
    if next_offset >= len(items):
        next_offset = None
    return {"ok": True, "data": items[offset: offset + count], "next_offset": next_offset}


def get_entry_points() -> dict:
    result = []
    for i in range(ida_entry.get_entry_qty()):
        ordinal = ida_entry.get_entry_ordinal(i)
        address = ida_entry.get_entry(ordinal)
        fn = ida_funcs.get_func(address)
        if fn:
            result.append(_func_info(fn))
    return {"ok": True, "entries": result}
