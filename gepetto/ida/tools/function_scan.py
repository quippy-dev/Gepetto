import json
from typing import Dict, List

import ida_bytes
import ida_funcs
import ida_kernwin
import ida_name
import ida_strlist
import ida_xref
import idautils
import idc

from gepetto.ida.tools.tools import add_result_to_messages
from gepetto.ida.utils.ida9_utils import run_on_main_thread, parse_ea


def handle_get_function_immediates_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}
    try:
        result = get_function_immediates(args.get("function_address"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_get_function_strings_tc(tc, messages):
    try:
        args = json.loads(getattr(tc.function, "arguments", "") or "{}")
    except Exception:
        args = {}
    try:
        result = get_function_strings(args.get("function_address"))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _func_bounds(ea: int):
    def _do():
        f = ida_funcs.get_func(ea)
        if not f:
            return None
        return int(f.start_ea), int(f.end_ea)
    return run_on_main_thread(_do, write=False)


def get_function_immediates(function_address: str) -> Dict:
    if not function_address:
        return {"ok": False, "error": "function_address is required"}
    ea = parse_ea(function_address)
    bounds = _func_bounds(ea)
    if not bounds:
        return {"ok": False, "error": "EA is not inside a function"}
    start, end = bounds

    imm_map: Dict[int, List[int]] = {}

    def _do():
        ea_it = start
        while ea_it < end:
            try:
                # Check up to 8 operands; IDA will return -1 for non-existent
                for op_idx in range(8):
                    t = idc.get_operand_type(ea_it, op_idx)
                    if t == idc.o_imm:
                        v = idc.get_operand_value(ea_it, op_idx)
                        imm_map.setdefault(int(ea_it), []).append(int(v))
            except Exception:
                pass
            nend = ida_bytes.get_item_end(ea_it)
            if not isinstance(nend, int) or nend <= ea_it:
                nend = ea_it + 1
            ea_it = nend
        return 1

    run_on_main_thread(_do, write=False)
    items = []
    for insn_ea, vals in imm_map.items():
        items.append({
            "ea": int(insn_ea),
            "values": [int(v) for v in vals],
        })
    return {"ok": True, "start": int(start), "end": int(end), "items": items}


def _snapshot_strings() -> List[Dict]:
    out = {"strings": []}

    def _ui():
        try:
            try:
                ida_strlist.build_strlist()
            except Exception:
                pass
            sv = idautils.Strings()
            sv.refresh()
            for si in sv:
                out["strings"].append({
                    "ea": int(si.ea),
                    "text": str(si),
                })
        except Exception:
            out["strings"] = []
        return 1

    run_on_main_thread(_ui, write=True)
    return out["strings"]


def _string_xrefs(ea: int) -> List[int]:
    xs = []
    def _do():
        xb = ida_xref.xrefblk_t()
        if xb.first_to(ea, ida_xref.XREF_FAR):
            while True:
                xs.append(int(xb.frm))
                if not xb.next_to():
                    break
        return 1
    run_on_main_thread(_do, write=False)
    return xs


def get_function_strings(function_address: str) -> Dict:
    if not function_address:
        return {"ok": False, "error": "function_address is required"}
    ea = parse_ea(function_address)
    bounds = _func_bounds(ea)
    if not bounds:
        return {"ok": False, "error": "EA is not inside a function"}
    start, end = bounds

    strings = _snapshot_strings()
    results = []
    for s in strings:
        se = s.get("ea")
        if not isinstance(se, int):
            continue
        for xr in _string_xrefs(se):
            if start <= xr < end:
                results.append({
                    "ea": se,
                    "text": s.get("text", ""),
                })
                break
    return {"ok": True, "start": int(start), "end": int(end), "strings": results}

