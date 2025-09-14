import json
from typing import List, Dict

import ida_kernwin
import ida_name
import ida_funcs
import ida_xref
import idautils

from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import run_on_main_thread


_DEFAULT_INPUT_FUNCS = [
    # C stdio / POSIX
    "gets", "fgets", "scanf", "sscanf", "getchar", "fgetc", "fread",
    # C11 safer variants
    "gets_s", "scanf_s", "sscanf_s", "fgets_s",
    # C++ streams
    "std::getline", "std::basic_istream", "operator>>",
    # Win32
    "ReadFile", "ReadConsoleA", "ReadConsoleW", "GetDlgItemTextA", "GetDlgItemTextW",
]


def handle_find_user_input_sites_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}
    try:
        names = args.get("names")
        result = find_user_input_sites(names if isinstance(names, list) else None)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_find_calls_to_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}
    try:
        result = find_calls_to(args.get("name_filter", ""))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _collect_targets_by_name(filter_substr: str) -> List[Dict]:
    """Enumerate all named symbols whose name contains the filter substring (case-insensitive)."""
    out = []
    f = filter_substr.lower()

    def _do():
        try:
            for ea, nm in idautils.Names():
                name = str(nm or "")
                if f in name.lower():
                    out.append({"ea": int(ea), "name": name})
        except Exception:
            pass
        return 1

    run_on_main_thread(_do, write=False)
    return out


def _xrefs_to(ea: int) -> List[int]:
    xs = []

    def _do():
        blk = ida_xref.xrefblk_t()
        if blk.first_to(ea, ida_xref.XREF_ALL):
            while True:
                xs.append(int(blk.frm))
                if not blk.next_to():
                    break
        return 1

    run_on_main_thread(_do, write=False)
    return xs


def _func_name(ea: int) -> str:
    def _do():
        f = ida_funcs.get_func(ea)
        if f:
            try:
                from gepetto.ida.tools.function_utils import get_func_name
                return get_func_name(f) or ""
            except Exception:
                return ida_name.get_ea_name(f.start_ea) or ""
        return ida_name.get_ea_name(ea) or ""
    return run_on_main_thread(_do, write=False)


def find_calls_to(name_filter: str) -> dict:
    if not name_filter:
        return {"ok": False, "error": "name_filter is required"}

    targets = _collect_targets_by_name(name_filter)
    calls = []
    for t in targets:
        for frm in _xrefs_to(t["ea"]):
            calls.append({
                "callee": {"ea": int(t["ea"]), "name": t["name"]},
                "call_site": {"ea": int(frm), "function": _func_name(frm)},
            })
    return {"ok": True, "calls": calls}


def find_user_input_sites(names: List[str] | None = None) -> dict:
    name_list = [str(n) for n in (names or _DEFAULT_INPUT_FUNCS)]
    out = []
    for nf in name_list:
        targets = _collect_targets_by_name(nf)
        for t in targets:
            for frm in _xrefs_to(t["ea"]):
                out.append({
                    "api": t["name"],
                    "api_ea": int(t["ea"]),
                    "call_site": {"ea": int(frm), "function": _func_name(frm)},
                })
    return {"ok": True, "sites": out}

