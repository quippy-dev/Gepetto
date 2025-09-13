import json

import ida_bytes

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_read_memory_bytes_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        addr = parse_ea(args.get("memory_address"))
        size = int(args.get("size", 0) or 0)
        if size <= 0:
            raise ValueError("size must be > 0")
        data = ida_bytes.get_bytes(addr, size) or b""
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
        reader = getattr(ida_bytes, reader_name)
        value = int(reader(ea))
        result = {"ok": True, "value": value}
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
        value = ida_bytes.get_qword(ea)
        result = {"ok": True, "value": int(value)}
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
        s = ida_bytes.get_strlit_contents(ea, -1, 0)
        result = {"ok": True, "value": s.decode("utf-8") if s else ""}
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)
