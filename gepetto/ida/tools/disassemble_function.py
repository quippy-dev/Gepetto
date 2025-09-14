import json

import ida_kernwin
import ida_funcs
import ida_lines
import ida_segment
import idaapi
import idc

from gepetto.ida.tools.function_utils import parse_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_disassemble_function_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    start_address = args.get("start_address")
    try:
        result = disassemble_function(start_address)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def disassemble_function(start_address: str) -> dict:
    if not start_address:
        return {"ok": False, "error": "start_address is required"}
    
    try:
        start = parse_ea(start_address)
        out = {"ok": False}

        def _do():
            try:
                func: ida_funcs.func_t = idaapi.get_func(start)
                if not func:
                    out.update(error=f"No function found containing address {start_address}")
                    return 0
                
                # Don't jump to address during automated tool execution for safety
                # ida_kernwin.jumpto(start)

                lines = []
                for address in ida_funcs.func_item_iterator_t(func):
                    try:
                        seg = ida_segment.getseg(address)
                        segment = ida_segment.get_segm_name(seg) if seg else None

                        label = idc.get_name(address, 0)
                        if label and label == func.name and address == func.start_ea:
                            label = None
                        if label == "":
                            label = None

                        comments = []
                        try:
                            if (c := idaapi.get_cmt(address, False)):
                                comments.append(c)
                            if (c2 := idaapi.get_cmt(address, True)):
                                comments.append(c2)
                        except Exception:
                            pass

                        try:
                            raw_instruction = ida_lines.generate_disasm_line(address, 0)
                            tls = ida_kernwin.tagged_line_sections_t()
                            ida_kernwin.parse_tagged_line_sections(tls, raw_instruction)
                            insn_section = tls.first(ida_lines.COLOR_INSN)

                            operands = []
                            for op_tag in range(ida_lines.COLOR_OPND1, ida_lines.COLOR_OPND8 + 1):
                                op_n = tls.first(op_tag)
                                if not op_n:
                                    break
                                op: str = op_n.substr(raw_instruction)
                                op_str = ida_lines.tag_remove(op)

                                # Attempt to add address comment annotations with better error handling
                                try:
                                    for idx in range(len(op) - 2):
                                        if op[idx] != idaapi.COLOR_ON:
                                            continue
                                        idx += 1
                                        if ord(op[idx]) != idaapi.COLOR_ADDR:
                                            continue
                                        idx += 1
                                        addr_string = op[idx:idx + idaapi.COLOR_ADDR_SIZE]
                                        idx += idaapi.COLOR_ADDR_SIZE
                                        try:
                                            a = int(addr_string, 16)
                                        except Exception:
                                            continue
                                        symbol = op[idx:op.find(idaapi.COLOR_OFF, idx)] or op_str
                                        comments.append(f"{symbol}={a:#x}")
                                except Exception:
                                    pass
                                    
                                operands.append(op_str)

                            mnem = ida_lines.tag_remove(insn_section.substr(raw_instruction)) if insn_section else ""
                            instruction = f"{mnem} {', '.join(operands)}".strip()
                        except Exception:
                            # Fallback to simple disassembly
                            instruction = idc.GetDisasm(address) or "<disasm error>"

                        line = {"address": f"{address:#x}", "instruction": instruction}
                        if comments:
                            line["comments"] = comments
                        if segment:
                            line["segment"] = segment
                        if label:
                            line["label"] = label
                        lines.append(line)
                    except Exception:
                        # Skip problematic instructions but continue
                        continue

                # prototype info (best-effort)
                rd = {"name": func.name, "start_ea": f"{func.start_ea:#x}", "stack_frame": [], "lines": lines}
                try:
                    proto = getattr(func, 'get_prototype', None)
                    if proto:
                        p = func.get_prototype()
                        if p:
                            rd["return_type"] = f"{p.get_rettype()}"
                            rd["arguments"] = [{"name": a.name, "type": f"{a.type}"} for a in p.iter_func()]
                except Exception:
                    pass

                out.update(ok=True, **rd)
                return 1
            except Exception as e:
                out.update(error=str(e))
                return 0

        # Use MFF_FAST for better compatibility
        if not ida_kernwin.execute_sync(_do, ida_kernwin.MFF_FAST):
            if not out.get("error"):
                out["error"] = "Failed to execute on main thread"
                
        return out
    except Exception as e:
        return {"ok": False, "error": f"Function disassembly failed: {str(e)}"}
