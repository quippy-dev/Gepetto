import json
import os
import time

import ida_kernwin
import ida_ida
import ida_idaapi
import ida_bytes
import idautils
import ida_strlist
import ida_segment

# Smoke checks for migrated tools.
# Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only.

# Tool modules
from gepetto.ida.tools import metadata as t_metadata
from gepetto.ida.tools import functions_info as t_funcs
from gepetto.ida.tools import globals_and_imports as t_globals
from gepetto.ida.tools import types_and_structures as t_types
from gepetto.ida.tools import stack_frame as t_frame
from gepetto.ida.tools import get_bytes as t_getbytes
from gepetto.ida.tools import search as t_search
from gepetto.ida.tools import memory as t_memory  # handler-based for some reads

RESULTS = {
    "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "ok": True,
    "items": []
}

def ui_read(callable_, *args, **kwargs):
    """Run callable on IDA UI thread with MFF_READ and return its value."""
    slot = {}
    def _do():
        try:
            slot["value"] = callable_(*args, **kwargs)
            slot["ok"] = True
        except Exception as e:
            slot["ok"] = False
            slot["error"] = str(e)
        return 1
    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
    if not slot.get("ok"):
        raise RuntimeError(slot.get("error", "unknown UI read error"))
    return slot.get("value")

def add_result(name, ok, payload=None, error=None):
    RESULTS["items"].append({
        "name": name,
        "ok": bool(ok),
        "payload": payload,
        "error": error
    })
    if not ok:
        RESULTS["ok"] = False

def first_function_ea():
    for ea in idautils.Functions():
        return int(ea)
    # fallback to start EA
    return int(ida_ida.inf_get_start_ea())

def first_string_ea():
    # Rebuild & snapshot strings list on the UI thread, similar to search.py
    def _snapshot():
        try:
            ida_strlist.build_strlist()
        except Exception:
            pass
        view = idautils.Strings()
        view.refresh()
        for si in view:
            return int(si.ea)
        return None
    return ui_read(_snapshot)

def run():
    try:
        # A) metadata
        add_result("get_metadata", True, t_metadata.get_metadata())

        # B) functions info
        add_result("get_current_address", True, t_funcs.get_current_address())
        add_result("list_functions", True, t_funcs.list_functions(0, 10))
        add_result("get_entry_points", True, t_funcs.get_entry_points())

        # C) globals/imports
        add_result("list_globals", True, t_globals.list_globals(0, 20))
        add_result("list_imports", True, t_globals.list_imports(0, 20))

        # D) types & structures
        add_result("list_local_types", True, t_types.list_local_types())
        add_result("get_defined_structures", True, t_types.get_defined_structures())
        add_result("search_structures", True, t_types.search_structures("struct"))

        # E) stack frame (best-effort)
        fea = first_function_ea()
        if fea:
            add_result("get_stack_frame_variables", True, t_frame.get_stack_frame_variables(f"{fea:#x}"))
        else:
            add_result("get_stack_frame_variables", True, {"note": "no functions found"})

        # F) memory bytes
        some_ea = fea or int(ida_ida.inf_get_start_ea())
        add_result("get_bytes", True, t_getbytes.get_bytes(some_ea, 16))

        # G) memory string via handler (requires a string EA)
        str_ea = first_string_ea()
        if str_ea:
            # Build a tc/messages pair to reuse the handler
            class _FN:
                def __init__(self, name, args_json):
                    self.name = name
                    self.arguments = args_json
            class _TC:
                def __init__(self, fn):
                    self.function = fn
                    self.id = "tc-1"
            messages = []
            args_json = json.dumps({"address": f"{str_ea:#x}"})
            tc = _TC(_FN("data_read_string", args_json))
            t_memory.handle_data_read_string_tc(tc, messages)
            add_result("data_read_string", True, messages)
        else:
            add_result("data_read_string", True, {"note": "no string literals found"})

        # H) hex/text search (accept empty results)
        # IDA 9.x port: ida_search.find_binary removed; use ida_bytes.find_bytes.
        add_result("search_hex", True, t_search.search(hex="90"))
        add_result("search_text", True, t_search.search(text="main"))

    except Exception as e:
        add_result("harness_error", False, error=str(e))

    # Store results
    out_path = os.path.join(os.getcwd(), "ida9_tool_test_results.json")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(RESULTS, f, ensure_ascii=False, indent=2)
        print(f"[IDA9 TEST] Wrote results to: {out_path}")
    except Exception as e:
        print(f"[IDA9 TEST] Failed to write results: {e}")
    print(f"[IDA9 TEST] Overall OK: {RESULTS['ok']} (items: {len(RESULTS['items'])})")

if __name__ == "__main__":
    run()