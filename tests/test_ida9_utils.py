import pytest

try:
    import idaapi  # type: ignore
    HAVE_IDA = True
except Exception:
    HAVE_IDA = False

from gepetto.ida.utils.ida9_utils import parse_ea, ea_to_hex


def test_parse_ea_int():
    assert parse_ea(0x10) == 16


def test_parse_ea_hex_string():
    assert parse_ea("0x2a") == 42
    assert parse_ea("2Ah") == 42


def test_parse_ea_decimal_string():
    assert parse_ea("42") == 42


@pytest.mark.skipif(not HAVE_IDA, reason="IDA not available")
def test_ea_to_hex_badaddr_is_BADADDR():
    import idaapi
    assert ea_to_hex(idaapi.BADADDR) == "BADADDR"


@pytest.mark.skipif(not HAVE_IDA, reason="IDA not available")
def test_safe_get_screen_ea_type():
    from gepetto.ida.utils.ida9_utils import safe_get_screen_ea
    ea = safe_get_screen_ea()
    assert isinstance(ea, int)