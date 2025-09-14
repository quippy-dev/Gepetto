import json

import ida_bytes
import ida_kernwin
import idaapi

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import touch_last_ea


def handle_read_memory_bytes_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        addr = parse_ea(args.get("memory_address"))
        touch_last_ea(addr)
        size = int(args.get("size", 0) or 0)
        if size <= 0:
            raise ValueError("size must be > 0")
        
        # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
        out = {"data": None}
        def _do():
            out["data"] = ida_bytes.get_bytes(addr, size) or b""
            return 1
        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        
        data = out["data"]
        result = {"ok": True, "bytes": " ".join(f"{x:#02x}" for x in data)}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _simple_read(tc, messages, reader_name: str):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        ea = parse_ea(args.get("address"))
        touch_last_ea(ea)
        
        # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
        out = {"value": None}
        def _do():
            reader = getattr(ida_bytes, reader_name)
            out["value"] = int(reader(ea))
            return 1
        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        
        result = {"ok": True, "value": out["value"]}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_data_read_byte_tc(tc, messages):
    _simple_read(tc, messages, "get_wide_byte")


def handle_data_read_word_tc(tc, messages):
    _simple_read(tc, messages, "get_wide_word")


def handle_data_read_dword_tc(tc, messages):
    _simple_read(tc, messages, "get_wide_dword")


def handle_data_read_qword_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        ea = parse_ea(args.get("address"))
        touch_last_ea(ea)
        touch_last_ea(ea)
        
        # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
        out = {"value": None}
        def _do():
            out["value"] = ida_bytes.get_qword(ea)
            return 1
        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        
        result = {"ok": True, "value": int(out["value"])}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_data_read_string_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        ea = parse_ea(args.get("address"))
        
        # Run on UI thread (IDA 9.x): many IDA APIs are main-thread-only
        out = {"data": None}
        def _do():
            out["data"] = idaapi.get_strlit_contents(ea, -1, 0)
            return 1
        ida_kernwin.execute_sync(_do, ida_kernwin.MFF_READ)
        
        s = out["data"]
        result = {"ok": True, "value": s.decode("utf-8") if s else ""}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)
