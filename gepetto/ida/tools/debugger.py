import json
import os

import ida_dbg
import ida_ida
import ida_idd
import ida_bytes
import ida_name
import idaapi

from gepetto.ida.utils.ida9_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_dbg_get_registers_tc(tc, messages):
    try:
        result = dbg_get_registers()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_dbg_get_call_stack_tc(tc, messages):
    try:
        result = dbg_get_call_stack()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_dbg_list_breakpoints_tc(tc, messages):
    try:
        result = dbg_list_breakpoints()
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_dbg_start_process_tc(tc, messages):
    add_result_to_messages(messages, tc, {"ok": True, "message": "Debugger started" if idaapi.start_process("", "", "") else "Failed to start debugger"})


def handle_dbg_exit_process_tc(tc, messages):
    add_result_to_messages(messages, tc, {"ok": True, "message": "Debugger exited" if idaapi.exit_process() else "Failed to exit debugger"})


def handle_dbg_continue_process_tc(tc, messages):
    add_result_to_messages(messages, tc, {"ok": True, "message": "Debugger continued" if idaapi.continue_process() else "Failed to continue debugger"})


def handle_dbg_run_to_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    ea = parse_ea(args.get("address"))
    ok = idaapi.run_to(ea)
    add_result_to_messages(messages, tc, {"ok": ok, "message": f"Debugger run to {hex(ea)}" if ok else f"Failed to run to {hex(ea)}"})


def handle_dbg_set_breakpoint_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    ea = parse_ea(args.get("address"))
    ok = idaapi.add_bpt(ea, 0, idaapi.BPT_SOFT)
    msg = f"Breakpoint set at {hex(ea)}" if ok else f"Failed to set breakpoint at {hex(ea)}"
    add_result_to_messages(messages, tc, {"ok": ok, "message": msg})


def handle_dbg_delete_breakpoint_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    ea = parse_ea(args.get("address"))
    ok = idaapi.del_bpt(ea)
    msg = f"Breakpoint deleted at {hex(ea)}" if ok else f"Failed to delete breakpoint at {hex(ea)}"
    add_result_to_messages(messages, tc, {"ok": ok, "message": msg})


def handle_dbg_enable_breakpoint_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    ea = parse_ea(args.get("address"))
    enable = bool(args.get("enable", True))
    ok = idaapi.enable_bpt(ea, enable)
    msg = f"Breakpoint {'enabled' if enable else 'disabled'} at {hex(ea)}" if ok else f"Failed to {'enable' if enable else 'disable'} breakpoint at {hex(ea)}"
    add_result_to_messages(messages, tc, {"ok": ok, "message": msg})


def dbg_get_registers() -> dict:
    result = []
    dbg = ida_idd.get_dbg()
    for thread_index in range(ida_dbg.get_thread_qty()):
        tid = ida_dbg.getn_thread(thread_index)
        regs_out = []
        regvals = ida_dbg.get_reg_vals(tid)
        for reg_index, rv in enumerate(regvals):
            reg_info = dbg.regs(reg_index)
            reg_value = rv.pyval(reg_info.dtype)
            if isinstance(reg_value, int):
                reg_value = hex(reg_value)
            if isinstance(reg_value, bytes):
                reg_value = reg_value.hex(" ")
            regs_out.append({"name": reg_info.name, "value": reg_value})
        result.append({"thread_id": tid, "registers": regs_out})
    return {"ok": True, "threads": result}


def dbg_get_call_stack() -> dict:
    callstack = []
    try:
        tid = ida_dbg.get_current_thread()
        trace = ida_idd.call_stack_t()
        if not ida_dbg.collect_stack_trace(tid, trace):
            return {"ok": True, "frames": []}
        for frame in trace:
            frame_info = {"address": int(frame.callea)}
            try:
                module_info = ida_idd.modinfo_t()
                if ida_dbg.get_module_info(frame.callea, module_info):
                    frame_info["module"] = os.path.basename(module_info.name)
                else:
                    frame_info["module"] = "<unknown>"
                name = ida_name.get_nice_colored_name(frame.callea, ida_name.GNCN_NOCOLOR | ida_name.GNCN_NOLABEL | ida_name.GNCN_NOSEG | ida_name.GNCN_PREFDBG) or "<unnamed>"
                frame_info["symbol"] = name
            except Exception as e:
                frame_info["module"] = "<error>"
                frame_info["symbol"] = str(e)
            callstack.append(frame_info)
    except Exception:
        pass
    return {"ok": True, "frames": callstack}


def dbg_list_breakpoints() -> dict:
    ea = ida_ida.inf_get_min_ea()
    end_ea = ida_ida.inf_get_max_ea()
    breakpoints = []
    while ea <= end_ea:
        bpt = ida_dbg.bpt_t()
        if ida_dbg.get_bpt(ea, bpt):
            breakpoints.append({
                "ea": int(bpt.ea),
                "type": int(bpt.type),
                "enabled": bool(bpt.flags & ida_dbg.BPT_ENABLED),
                "condition": bpt.condition if bpt.condition else None,
            })
        ea = ida_bytes.next_head(ea, end_ea)
    return {"ok": True, "breakpoints": breakpoints}
