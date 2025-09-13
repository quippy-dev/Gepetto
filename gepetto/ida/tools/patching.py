import json

import ida_bytes
import idautils
import ida_kernwin

from gepetto.ida.tools.function_utils import parse_ea
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
        raise ValueError(f"Failed to assemble instruction: {assemble}")
    ida_bytes.patch_bytes(ea, bytes_to_patch)
    return len(bytes_to_patch)


def patch_address_assembles(address: str, assembles: str) -> dict:
    if not assembles:
        raise ValueError("assembles is required (semicolon separated)")
    ea = parse_ea(address)
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

    ida_kernwin.execute_sync(_do, ida_kernwin.MFF_WRITE)
    return out

