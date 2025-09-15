import json

import ida_bytes
import idautils
import ida_kernwin

from gepetto.ida.utils.ida9_utils import parse_ea, run_on_main_thread, touch_last_ea
from gepetto.ida.tools.tools import add_result_to_messages


def handle_patch_address_assembles_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = patch_address_assembles(args.get("address"), args.get("assembles", ""))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def _patch_assemble(ea: int, assemble: str) -> int:
    ok, bytes_to_patch = idautils.Assemble(ea, assemble)
    if not ok:
        raise ValueError(_("Failed to assemble instruction: {assemble}").format(assemble=assemble))
    ida_bytes.patch_bytes(ea, bytes_to_patch)
    return len(bytes_to_patch)


def patch_address_assembles(address: str, assembles: str) -> dict:
    if not assembles:
        raise ValueError(_("assembles is required (semicolon separated)"))
    ea = parse_ea(address)
    touch_last_ea(ea)
    out = {"ok": False}

    def _do():
        try:
            count = 0
            cur = ea
            for assemble in assembles.split(";"):
                asm = assemble.strip()
                if not asm:
                    continue
                consumed = _patch_assemble(cur, asm)
                cur += consumed
                count += 1
            out.update(ok=True, message=f"Patched {count} instructions")
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    run_on_main_thread(_do, write=True)
    return out


def handle_patch_nop_instructions_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = patch_nop_instructions(args.get("address"), int(args.get("count", 1) or 1))
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def handle_patch_force_fallthrough_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    try:
        result = patch_nop_instructions(args.get("address"), 1)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def patch_nop_instructions(address: str, count: int = 1) -> dict:
    if not address:
        raise ValueError(_("address is required"))
    if count <= 0:
        raise ValueError(_("count must be >= 1"))
    ea = parse_ea(address)
    touch_last_ea(ea)
    out = {"ok": False}

    def _do():
        try:
            import ida_bytes
            cur = ea
            patched = 0
            for _ in range(int(count)):
                end = ida_bytes.get_item_end(cur)
                if not isinstance(end, int) or end <= cur:
                    out.update(error=f"Failed to determine instruction boundary at {hex(cur)}")
                    return 0
                length = int(end - cur)
                wrote = 0
                sub = cur
                while wrote < length:
                    consumed = _patch_assemble(sub, "nop")
                    if consumed <= 0:
                        out.update(error=f"Assemble failed at {hex(sub)} for NOP")
                        return 0
                    sub += consumed
                    wrote += consumed
                patched += 1
                cur = end  # advance to next original instruction start
            out.update(ok=True, message=f"NOPed {patched} instruction(s)")
            return 1
        except Exception as e:
            out.update(error=str(e))
            return 0

    run_on_main_thread(_do, write=True)
    return out

