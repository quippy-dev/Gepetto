import json

from gepetto.ida.tools.tools import add_result_to_messages


def handle_convert_number_tc(tc, messages):
    try:
        args = json.loads(tc.function.arguments or "{}")
    except Exception:
        args = {}
    text = args.get("text") or ""
    size = args.get("size")
    try:
        result = convert_number(text=text, size=size)
    except Exception as ex:
        result = {"ok": False, "error": str(ex)}
    add_result_to_messages(messages, tc, result)


def convert_number(text: str, size: int | None) -> dict:
    if not text:
        raise ValueError(_("text is required"))
    try:
        value = int(text, 0)
    except ValueError:
        raise ValueError(_("Invalid number: {text}").format(text=text))

    if not size:
        n = abs(value)
        bits = 0
        while n:
            bits += 1
            n >>= 1
        bits = max(bits, 1)
        size = (bits + 7) // 8

    try:
        b = value.to_bytes(size, "little", signed=True)
    except OverflowError:
        raise ValueError(_("Number {text} is too big for {size} bytes").format(text=text, size=size))

    ascii_s = ""
    for byte in b.rstrip(b"\x00"):
        if 32 <= byte <= 126:
            ascii_s += chr(byte)
        else:
            ascii_s = None
            break

    return {
        "ok": True,
        "decimal": str(value),
        "hexadecimal": hex(value),
        "bytes": b.hex(" "),
        "ascii": ascii_s,
        "binary": bin(value),
    }

